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

namespace GeboSigChangePIN
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void addLog(string text, bool isError = true)
        {
            if (isError) {
                textLog.Text = textLog.Text + "Error:";
            }
            textLog.Text = textLog.Text + string.Format($"{text}\r\n");
        }

        private async void ButtonChangePIN_Click(object sender, RoutedEventArgs e)
        {
            string currentpin = textCurrentPIN.Text;
            string newpin = textNewPIN.Text;
            // 入力チェック
            if (string.IsNullOrEmpty(currentpin)) {
                addLog("現在のPINを入力してください");
                return ;
            }
            if (string.IsNullOrEmpty(newpin)) {
                addLog("新しいPINを入力してください");
                return ;
            }

            var devParam = gebo.CTAP2.DevParam.GetDefaultParams();
            var ret = await gebo.CTAP2.WebAuthnModokiDesktop.Credentials.ChangePin(devParam, newpin, currentpin);
            if (ret.isSuccess == true) {
                addLog("PIN変更OK",false);
                MessageBox.Show("PIN変更OK");
            } else {
                addLog(ret.msg);
                addLog("PIN変更NG");
            }

            return;
        }

    }
}
