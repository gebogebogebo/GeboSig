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

            {
                string command = "";

                command = "openssl x509 -in TestUser.crt -pubkey -noout>public-key.pem";
                textLog.Text = textLog.Text + string.Format($"{command}\r\n");

                command = "openssl dgst -sha1 -verify public-key.pem -signature sig.sig とっても大事な文書.pdf";
                textLog.Text = textLog.Text + string.Format($"{command}\r\n");

            }
        }

        private void ButtonVerify_Click(object sender, RoutedEventArgs e)
        {
            // input 
            string file_in_sig = @"C:\work\sig.sig";
            string file_in_target = @"C:\work\とっても大事な文書.pdf";

            var publicKey = readPublicKeyfromCert(@"C:\work\TestUser.crt");

            ISigner signer = SignerUtilities.GetSigner(GeboSigCommon.Common.SigAlgorithm);
            signer.Init(false, publicKey);

            // 一回よみこまないといけないの？！・・・
            var expectedSig = System.IO.File.ReadAllBytes(file_in_sig);

            // Get the bytes to be signed from the string
            var msgBytes = System.IO.File.ReadAllBytes(file_in_target);

            // Calculate the signature and see if it matches
            signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
            var result =  signer.VerifySignature(expectedSig);

            textLog.Text = string.Format($"{result}\r\n");

            return;
        }

        // 署名作成はここが参考になるかも
        // https://codeday.me/jp/qa/20190217/287736.html

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
