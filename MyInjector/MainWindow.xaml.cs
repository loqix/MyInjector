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
            cbx_process_list.DataContext = processListSource;
        }

        private void cbx_process_list_DropDownOpened(object sender, EventArgs e)
        {
            cbx_process_list.GetBindingExpression(ComboBox.ItemsSourceProperty).UpdateTarget();
        }

        private ProcessListSource processListSource = new ProcessListSource();

        private int GetTargetPID()
        {
            string data = cbx_process_list.SelectedItem as string;
            data = data.Substring(0, data.IndexOf('\t'));
            return int.Parse(data);
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
}
