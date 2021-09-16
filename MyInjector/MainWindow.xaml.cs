using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using Microsoft.Win32;
using System.Threading;
using System.Runtime.InteropServices;

namespace MyInjector
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            ComboBox_ProcessList.DataContext = processListSource;
            SetTextboxPlaceholder(TextBox_DllPath, dllPath_PlaceholderText);

            WindowFramePainter.Start();
        }

        private void ComboBox_ProcessList_DropDownOpened(object sender, EventArgs e)
        {
            ComboBox_ProcessList.GetBindingExpression(ComboBox.ItemsSourceProperty).UpdateTarget();
        }

        private ProcessListSource processListSource = new ProcessListSource();

        private int GetTargetPID()
        {
            string data = ComboBox_ProcessList.SelectedItem as string;
            data = data.Substring(0, data.IndexOf('\t'));
            return int.Parse(data);
        }

        private string GetTargetDllPath()
        {
            return TextBox_DllPath.Text;
        }

        private void TextBox_DllPath_PreviewDragOver(object sender, DragEventArgs e)
        {
            if (!(e.Data.GetData(DataFormats.FileDrop) is string[] fileNames))
            {
                return;
            }
            var fileName = fileNames.FirstOrDefault();
            if (fileName == null)
            {
                return;
            }
            (sender as TextBox).Text = fileName;
            e.Handled = true;
        }

        private readonly string dllPath_PlaceholderText = "Drag and drop your dll file here";

        private void TextBox_DllPath_GotFocus(object sender, RoutedEventArgs e)
        {
            var self = sender as TextBox;
            if (self.Text.Equals(dllPath_PlaceholderText))
            {
                self.Text = "";
                self.Foreground = Brushes.Black;
            }
        }

        private void TextBox_DllPath_LostFocus(object sender, RoutedEventArgs e)
        {
            var self = sender as TextBox;
            if (self.Text.Length == 0)
            {
                SetTextboxPlaceholder(self, dllPath_PlaceholderText);
            }
        }

        private void SetTextboxPlaceholder(TextBox tbx, string text)
        {
            tbx.Text = text;
            tbx.Foreground = Brushes.Gray;
        }

        private void Button_OpenDll_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "DLL file|*.dll|All files|*.*";
            if (dialog.ShowDialog() == true)
            {
                TextBox_DllPath.Foreground = Brushes.Black;
                TextBox_DllPath.Text = dialog.FileName;
            }
        }
    }

    public class ProcessListSource
    {
        public IEnumerable<string> ProcessList
        {
            get
            {
                var ret = new List<string>();
                var plist = Process.GetProcesses();
                Array.Sort(plist, delegate (Process process1, Process process2)
                {
                    return process1.Id.CompareTo(process2.Id);
                });

                foreach (var process in plist)
                {
                    var pid = process.Id;
                    var pname = process.ProcessName;
                    var content = String.Format("{0}\t{1}", pid, pname);
                    ret.Add(content);
                }
                return ret;
            }
        }
    }

    public static class WindowFramePainter
    {
        public static void DrawRectangleAtPos(Point topLeft, Point buttomRight)
        {
            marker = new MarkerWindow
            {
                Height = buttomRight.Y - topLeft.Y,
                Width = buttomRight.X - topLeft.X,
                Left = topLeft.X,
                Top = topLeft.Y
            };
            marker.Show();
        }

        public static void Clear()
        {
            marker.Close();
            marker = null;
        }

        public static void Start()
        {

        }

        public static void Stop()
        {
            ;
        }

        private static void Worker()
        {
            while (!exitFlag)
            {
                Thread.Sleep(200);

                NativePoint point;
                point.x = 200;
                point.y = 200;
                var window = WindowFromPoint(point);
                RECT rect;
                GetWindowRect(window, out rect);

                Point topleft = new Point(rect.Left, rect.Top);
                Point buttomright = new Point(rect.Right, rect.Bottom);
                DrawRectangleAtPos(topleft, buttomright);
            }
        }

        public static Process CurrentProcess { get; private set; }

        private static bool exitFlag = false;
        private static MarkerWindow marker = null;
        private static Thread painterThread = null;
        private static Int64 currentWindowHandle = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;        // x position of upper-left corner
            public int Top;         // y position of upper-left corner
            public int Right;       // x position of lower-right corner
            public int Bottom;      // y position of lower-right corner
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativePoint
        {
            public int x;
            public int y; 
        }

        [DllImport("user32.dll")]
        private static extern IntPtr WindowFromPoint(NativePoint p);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetWindowRect(IntPtr hwnd, out RECT lpRect);
    }
}
