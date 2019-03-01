using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.IO.Compression;

namespace GeboSigVerify
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            addLog("openSSLでやる場合は以下のコマンド", false);
            addLog("openssl x509 -in TestUser.crt -pubkey -noout>public-key.pem",false);
            addLog("openssl dgst -sha1 -verify public-key.pem -signature sig.sig とっても大事な文書.pdf",false);
        }

        private void addLog(string text, bool isError = true)
        {
            if (isError) {
                textLog.Text = textLog.Text + "Error:";
            }
            textLog.Text = textLog.Text + string.Format($"{text}\r\n");
        }

        private void ButtonSelect_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true)
            {
                textTargetFile.Text = dialog.FileName;
            }
        }

        private void ButtonSelectCrt_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true)
            {
                textTargetCrt.Text = dialog.FileName;
            }
        }

        private void ButtonVerify_Click(object sender, RoutedEventArgs e)
        {
            addLog("Verify Start!",false);
            bool result = false;
            string resultMsg = "";

            try {
                // input 
                string file_in_zip = textTargetFile.Text;
                if (string.IsNullOrEmpty(file_in_zip)) {
                    addLog("署名されたファイルを指定してください");
                    return;
                }

                string file_in_crt = textTargetCrt.Text;
                if (string.IsNullOrEmpty(file_in_crt)) {
                    addLog("作成者の証明書ファイルを指定してください");
                    return;
                }

                byte[] msgBytes;
                byte[] expectedSig;
                if (getVerifyFileandSig(file_in_zip, out msgBytes, out expectedSig) == false) {
                    // error
                    addLog("署名ファイルの読み込み失敗");
                    return;
                }

                var publicKey = readPublicKeyfromCert(file_in_crt);
                if (publicKey == null) {
                    addLog("証明書ファイルの読み込み失敗");
                    return;
                }

                ISigner signer = SignerUtilities.GetSigner(GeboSigCommon.Common.SigAlgorithm);
                signer.Init(false, publicKey);

                // Calculate the signature and see if it matches
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                result = signer.VerifySignature(expectedSig);

                resultMsg = string.Format($"検証結果={result}");
                addLog(resultMsg, false);

            } catch (Exception ex) {
                addLog("Verify");
            }

            addLog("Verify End!", false);

            if (result) {
                MessageBox.Show(resultMsg,"おめでとうございます");
            } else {
                MessageBox.Show(resultMsg,"ざんねんでした");
            }

            return;
        }

        private bool getVerifyFileandSig(string zip,out byte[] target, out byte[] sig)
        {
            target = null;
            sig = null;
            using (ZipArchive archive = ZipFile.OpenRead(zip)) {
                if( archive.Entries.Count != 2) {
                    return false;
                }

                foreach (ZipArchiveEntry entry in archive.Entries) {
                    if (entry.Name == "sig.sig") {
                        sig = new byte[entry.Length];
                        using (Stream stream = entry.Open()) {
                            var result = stream.Read(sig, 0, (int)entry.Length);
                        }
                    } else {
                        target = new byte[entry.Length];
                        using (Stream stream = entry.Open()) {
                            var result = stream.Read(target, 0, (int)entry.Length);
                        }
                    }
                }
            }
            return true;
        }

        private AsymmetricKeyParameter readPublicKeyfromCert(string certFile)
        {
            Org.BouncyCastle.X509.X509Certificate readedCert;

            // 証明書の読み込み
            using (var reader = new StreamReader(certFile, Encoding.ASCII)) {
                var pemReader = new PemReader(reader);
                readedCert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();
            }

            var publicKey = readedCert.GetPublicKey();

            return (publicKey);
        }

    }
}
