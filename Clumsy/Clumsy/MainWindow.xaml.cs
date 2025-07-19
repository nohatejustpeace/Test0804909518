using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Newtonsoft.Json;
using System.IO;
using System.Windows;

namespace ClumsyCloneWPF
{
    public partial class MainWindow : Window
    {
        private ICaptureDevice device;
        private bool running = false;
        private CancellationTokenSource cts;

        // Preset data model
        public class Preset
        {
            public int DelayMs { get; set; }
            public int DropPercent { get; set; }
            public int DuplicatePercent { get; set; }
            public int ThrottleKbps { get; set; }
            public bool DelayEnabled { get; set; }
            public bool DropEnabled { get; set; }
            public bool DuplicateEnabled { get; set; }
            public bool ThrottleEnabled { get; set; }
            public int LagJitterMs { get; set; }
            public bool LagEnabled { get; set; }
        }

        private Random random = new Random();
        private DateTime lastSentTime = DateTime.MinValue;
        private long bytesSentInInterval = 0;

        public MainWindow()
        {
            InitializeComponent();
            LoadInterfaces();
            ButtonStop.IsEnabled = false;
        }

        private void LoadInterfaces()
        {
            try
            {
                var devices = CaptureDeviceList.Instance;

                if (devices.Count < 1)
                {
                    MessageBox.Show("No devices found. Make sure Npcap is installed and running as admin.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                ComboInterfaces.Items.Clear();
                foreach (var dev in devices)
                {
                    ComboInterfaces.Items.Add($"{dev.Name} - {dev.Description}");
                }
                if (ComboInterfaces.Items.Count > 0)
                    ComboInterfaces.SelectedIndex = 0;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error loading interfaces: " + ex.Message);
            }
        }

        private async void ButtonStart_Click(object sender, RoutedEventArgs e)
        {
            if (ComboInterfaces.SelectedIndex < 0)
            {
                MessageBox.Show("Please select a network interface.");
                return;
            }

            var devices = CaptureDeviceList.Instance;
            device = devices[ComboInterfaces.SelectedIndex];

            try
            {
                if (device is LibPcapLiveDevice liveDevice)
                {
                    liveDevice.Open(DeviceModes.Promiscuous, 1000);
                }
                else
                {
                    MessageBox.Show("Selected device is not a LibPcapLiveDevice. Cannot open.");
                    return;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error opening device: " + ex.Message);
                return;
            }

            running = true;
            cts = new CancellationTokenSource();

            ButtonStart.IsEnabled = false;
            ButtonStop.IsEnabled = true;
            UpdateStatus("Status: Running...");

            try
            {
                await Task.Run(() => CaptureLoop(cts.Token));
            }
            catch (OperationCanceledException)
            {
                // Expected on cancel
            }
            catch (Exception ex)
            {
                UpdateStatus("Error during capture: " + ex.Message);
            }
        }

        private void ButtonStop_Click(object sender, RoutedEventArgs e)
        {
            StopCapture();
        }

        private void StopCapture()
        {
            if (!running) return;

            cts.Cancel();

            try
            {
                device?.Close();
            }
            catch { /* ignore exceptions on close */ }

            running = false;

            Dispatcher.Invoke(() =>
            {
                ButtonStart.IsEnabled = true;
                ButtonStop.IsEnabled = false;
                UpdateStatus("Status: Stopped");
            });
        }

        private void UpdateStatus(string text)
        {
            Dispatcher.Invoke(() =>
            {
                TextStatus.Content = text;  // Assuming TextStatus is a Label
            });
        }

        private void CaptureLoop(CancellationToken token)
        {
            device.OnPacketArrival += async (sender, e) =>
            {
                if (!running || token.IsCancellationRequested)
                    return;

                try
                {
                    var rawPacket = e.GetPacket();
                    var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                    if (CheckDrop.IsChecked == true)
                    {
                        int dropPercent = int.TryParse(TextDrop.Text, out var dr) ? dr : 0;
                        if (random.Next(100) < dropPercent)
                        {
                            // drop packet, do not send
                            return;
                        }
                    }

                    if (CheckDelay.IsChecked == true)
                    {
                        int baseDelay = int.TryParse(TextDelay.Text, out var dly) ? dly : 0;
                        int lagMs = 0;
                        if (CheckLag.IsChecked == true)
                        {
                            int jitter = int.TryParse(TextLag.Text, out var j) ? j : 0;
                            lagMs = random.Next(-jitter, jitter + 1);
                        }
                        int finalDelay = Math.Max(0, baseDelay + lagMs);
                        await Task.Delay(finalDelay, token);
                    }

                    if (CheckDuplicate.IsChecked == true)
                    {
                        int duplicatePercent = int.TryParse(TextDuplicate.Text, out var du) ? du : 0;
                        if (random.Next(100) < duplicatePercent)
                        {
                            if (device is IInjectionDevice injectDevice)
                            {
                                injectDevice.SendPacket(rawPacket);
                                injectDevice.SendPacket(rawPacket);
                            }
                            return;
                        }
                    }

                    if (CheckThrottle.IsChecked == true)
                    {
                        int throttleKbps = int.TryParse(TextThrottle.Text, out var thr) ? thr : 0;
                        double intervalSeconds = 0.1;
                        long maxBytesPerInterval = (long)(throttleKbps * 1024 / 8 * intervalSeconds);

                        if ((DateTime.Now - lastSentTime).TotalSeconds > intervalSeconds)
                        {
                            lastSentTime = DateTime.Now;
                            bytesSentInInterval = 0;
                        }

                        if (bytesSentInInterval + rawPacket.Data.Length > maxBytesPerInterval)
                        {
                            await Task.Delay(50, token);
                        }
                        bytesSentInInterval += rawPacket.Data.Length;
                    }

                    if (device is IInjectionDevice injector)
                    {
                        injector.SendPacket(rawPacket);
                    }
                }
                catch (OperationCanceledException)
                {
                    // cancellation expected, just return
                }
                catch (Exception)
                {
                    // ignore other exceptions to keep capture alive
                }
            };

            device.StartCapture();

            try
            {
                while (!token.IsCancellationRequested)
                {
                    Task.Delay(100, token).Wait();
                }
            }
            catch (OperationCanceledException)
            {
                // expected on cancellation
            }
            finally
            {
                device.StopCapture();
                device.OnPacketArrival -= null; // unregister all handlers
            }
        }

        private void ButtonSavePreset_Click(object sender, RoutedEventArgs e)
        {
            var preset = new Preset
            {
                DelayMs = int.TryParse(TextDelay.Text, out var d) ? d : 0,
                DropPercent = int.TryParse(TextDrop.Text, out var dr) ? dr : 0,
                DuplicatePercent = int.TryParse(TextDuplicate.Text, out var du) ? du : 0,
                ThrottleKbps = int.TryParse(TextThrottle.Text, out var t) ? t : 0,
                DelayEnabled = CheckDelay.IsChecked == true,
                DropEnabled = CheckDrop.IsChecked == true,
                DuplicateEnabled = CheckDuplicate.IsChecked == true,
                ThrottleEnabled = CheckThrottle.IsChecked == true,
                LagJitterMs = int.TryParse(TextLag.Text, out var lj) ? lj : 0,
                LagEnabled = CheckLag.IsChecked == true
            };

            var dlg = new SaveFileDialog
            {
                Filter = "JSON Files|*.json",
                Title = "Save Preset"
            };

            if (dlg.ShowDialog() == true)
            {
                try
                {
                    string json = JsonConvert.SerializeObject(preset, Formatting.Indented);
                    File.WriteAllText(dlg.FileName, json);
                    UpdateStatus($"Status: Preset saved to {dlg.FileName}");
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error saving preset: " + ex.Message);
                }
            }
        }

        private void ButtonLoadPreset_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter = "JSON Files|*.json",
                Title = "Load Preset"
            };

            if (dlg.ShowDialog() == true)
            {
                try
                {
                    string json = File.ReadAllText(dlg.FileName);
                    var preset = JsonConvert.DeserializeObject<Preset>(json);
                    if (preset != null)
                    {
                        TextDelay.Text = preset.DelayMs.ToString();
                        TextDrop.Text = preset.DropPercent.ToString();
                        TextDuplicate.Text = preset.DuplicatePercent.ToString();
                        TextThrottle.Text = preset.ThrottleKbps.ToString();
                        TextLag.Text = preset.LagJitterMs.ToString();

                        CheckDelay.IsChecked = preset.DelayEnabled;
                        CheckDrop.IsChecked = preset.DropEnabled;
                        CheckDuplicate.IsChecked = preset.DuplicateEnabled;
                        CheckThrottle.IsChecked = preset.ThrottleEnabled;
                        CheckLag.IsChecked = preset.LagEnabled;

                        UpdateStatus($"Status: Preset loaded from {dlg.FileName}");
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error loading preset: " + ex.Message);
                }
            }
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            StopCapture();
            base.OnClosing(e);
        }
    }
}


