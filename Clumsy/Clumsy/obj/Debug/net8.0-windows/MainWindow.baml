   M S B A M L   `   `   `  ����
  Clumsy    ClumsyCloneWPF.MainWindow   5   	   W SPresentationCore, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   R NSystem.Xaml, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	     � Title$  Clumsy Clone��5   	   $	��450��6   $	��800��6+    � 
ResizeMode$ 	CanResize=�5   	    � WindowStartupLocation$ CenterScreen=�5   	   .��5      � $��10q�6    � RowDefinitions 5	   
   �� 5
      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $��* �6   �� 5      $
��Auto �6    � ColumnDefinitions 5   
   �� 5      $
��Auto �6   �� 5      $��* �6   �� 5      $
��Auto �6   .+�5   
   �� $��Select Network Interface:��6   $��0��64   $��0��6A   $��0,0,10,0q�6Q   $��Center=�6c   �� 5   
   -   5         ��Name$ deviceComboBox��5      $��0��6+   $��1��68   $	��500��6H   $��0,0,10,0q�6T   �� 5   
    �� Orientation$ 
Horizontal=�6   $��0��6.   $��2��6;   .+�5      �� -   5         ��Name$ startButton��5      $��Start��6*   $��75��6T   $��0,0,10,0q�6_   �� 5      -   5        $ 
stopButton��5      $
��Stop��6)   $��75��6Q   5      �� 5    
   -   5         ��Name$ 
logTextBox��5       $��2��6&   $��0��63   $��3��6C   $��	0,10,0,10q�6W   "	 �� VerticalScrollBarVisibility$
	 Auto=�5!      $
 �� HorizontalScrollBarVisibility$

 Auto=�65    �� TextWrapping$
 Wrap=�5"       �� AcceptsReturn$
 True��6&    �� 
IsReadOnly$
 True��6;   $��Consolas)�5#      $��12(�6(   ���#1e1e1e
�������6K   �� 5&   
   -   5         ��Name$ statusLabel��5&      $��3��6%   $��0��62   $��3��6B   $��Status: Idle��6V   $
��Left=�5'      $��Bottom=�6+   $
��Bold"�6F   
��� d �6X   5(      5)      