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

using System.IO;

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

using GeboSigCommon;
using Org.BouncyCastle.Security;
using System.IO.Compression;

namespace GeboSigSignature
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

        private async void ButtonSignature_Click(object sender, RoutedEventArgs e)
        {
            // input
            string file_in_target = textTargetFile.Text;

            // output
            //string file_out_sig = string.Format($"{textSigPath.Text}sig.sig");

            textLog.Text = textLog.Text + string.Format($"Read-Start ... ");

            var readData = await readRecs(GeboSigCommon.Common.RPID, textPIN.Text);
            textLog.Text = textLog.Text + string.Format($"...{readData.msg}") + "\r\n";

            if (readData.isSuccess == false) {
                return;
            }

            // DER to PEM
            var privateKeyPem = GeboSigCommon.Common.ConvertPrivateKeyDERtoPEM(readData.data);

            // PEMフォーマットの秘密鍵を読み込んで KeyPair オブジェクトを生成
            var privateKeyReader = new PemReader(new StringReader(privateKeyPem));
            var keyPair = (AsymmetricCipherKeyPair)privateKeyReader.ReadObject();

            // 署名作成
            var sig = createSign(keyPair, System.IO.File.ReadAllBytes(file_in_target));

            /*
            {
                // RSA暗号標準オブジェクト(PKCS#1)を生成
                var rsa = new Pkcs1Encoding(new RsaEngine());

                // RSA暗号オブジェクトを初期化（第１引数 true は「暗号」を示す）
                rsa.Init(true, keyPair.Private);

                // 署名元データ生成
                var dgstinfo = GeboSigCommon.Common.CreateSHA1DigestInfo(file_in_target);

                // 暗号化されたバイト列を渡し、復号されたバイト列を受け取る
                byte[] sig = rsa.ProcessBlock(dgstinfo, 0, dgstinfo.Length);

                System.IO.File.WriteAllBytes(file_out_sig, sig);
            }
            */

            // ターゲットファイルと署名をzip
            createZip(file_in_target, sig);

            textLog.Text = textLog.Text + string.Format($"Signature ... Success!");

            return;
        }

        private bool createZip(string targetFile, byte[] sig)
        {
            var rootDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var targetFileTitle = System.IO.Path.GetFileNameWithoutExtension(targetFile);
            var targetFileName = System.IO.Path.GetFileName(targetFile);
            var zipFile = $@"{rootDir}\{targetFileTitle}.zip";

            // zipに固める
            using (var z = ZipFile.Open(zipFile, ZipArchiveMode.Update))
            {
                z.CreateEntryFromFile(targetFile, targetFileName, CompressionLevel.Optimal);

                ZipArchiveEntry item = z.CreateEntry("sig.sig",CompressionLevel.Optimal);
                using (Stream stream = item.Open())
                {
                    stream.Write(sig, 0, sig.Length);
                    stream.Flush();
                }
            }

            return true;
        }

        private async Task<ReadData> readRecs(string rpid,string pin)
        {
            ReadData result;
            try {

                result = await Task<ReadData>.Run(async () => {
                    var readData = new ReadData();

                    byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");
                    var credentialid = new byte[0];

                    string json =
                       "{" +
                            string.Format($"timeout : 60000,") +
                            string.Format($"challenge:[{string.Join(",", challenge)}],") +
                            string.Format($"rpId : '{rpid}',") +
                           @"allowCredentials : [{" +
                               string.Format($"id : [{string.Join(",", credentialid)}],") +
                               string.Format($"type : 'public-key',") +
                           @"}]," +
                           string.Format($"requireUserPresence : 'false',") +
                           string.Format($"userVerification : 'discouraged',") +
                        "}";

                    var ret = await WebAuthnModokiDesktop.credentials.get(gebo.CTAP2.DevParam.getDefaultParams(), json, pin);
                    if (ret.isSuccess == false) {
                        readData.isSuccess = false;
                        readData.msg = ret.msg;
                        return readData;
                    }

                    // dataList
                    var dataList = new List<WriteData>();
                    foreach (var assertion in ret.assertions) {
                        dataList.Add(new WriteData(assertion.User_Id, assertion.User_Name, assertion.User_DisplayName));
                    }
                    dataList = dataList.OrderBy(x => x.recno).ToList();

                    // data
                    readData.data = new byte[0];
                    foreach (var data in dataList) {
                        var tmp = data.data1.ToList().Concat(data.data2).Concat(data.data3).ToList();
                        readData.data = readData.data.ToList().Concat(tmp).ToArray();
                    }

                    readData.isSuccess = true;
                    readData.msg = "Success";
                    return readData;
                });

            } finally {

            }
            return result;
        }


        private byte[] createSign(AsymmetricCipherKeyPair keyPair, byte[] data)
        {
            // Make the key
            RsaKeyParameters key = (RsaKeyParameters)keyPair.Private;

            // Init alg
            ISigner sig = SignerUtilities.GetSigner(GeboSigCommon.Common.SigAlgorithm);

            // Populate key
            sig.Init(true, key);

            // Get the bytes to be signed from the string
            var bytes = data;

            // Calc the signature
            sig.BlockUpdate(bytes, 0, bytes.Length);
            byte[] signature = sig.GenerateSignature();

            // Base 64 encode the sig so its 8-bit clean
            //var signedString = Convert.ToBase64String(signature);

            return signature;
        }
    }
}
