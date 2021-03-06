﻿using System;
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
using GeboSigCommon;
using System.Diagnostics;
using Forms = System.Windows.Forms;

namespace GeboSigRegister
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

        private void ButtonSelect_Click(object sender, RoutedEventArgs e)
        {
            // フォルダー参照ダイアログのインスタンスを生成
            var dlg = new Forms.FolderBrowserDialog();

            // 説明文を設定
            dlg.Description = "フォルダーを選択してください。";

            // ダイアログを表示
            if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK) {
                // 選択されたフォルダーパスをメッセージボックスに表示
                textCert.Text = dlg.SelectedPath;
            }
        }

        private async void ButtonRegister_Click(object sender, RoutedEventArgs e)
        {
            // 入力チェック
            if( await checkInput(true) == false) {
                return;
            }

            // キーペアを作成
            var keyPair = createKeyPair(1024);

            // PrivateKeyをGET
            var pemPrivateKey = getPrivatekyPEM(keyPair);

            // PrivateKeyをDERにする
            var derPrivatekey = GeboSigCommon.Common.ConvertPEMtoDER(pemPrivateKey);
            Debug.WriteLine($"DER            {derPrivatekey.Length}:{gebo.CTAP2.Common.BytesToHexString(derPrivatekey)}");

            // AES(256)
            var encPrivatekey = BouncyCastleRijndael.Encrypt(derPrivatekey);
            Debug.WriteLine($"DER(Encrypted) {encPrivatekey.Length}:{gebo.CTAP2.Common.BytesToHexString(encPrivatekey)}");

            // 証明書を作成
            var cert = createCertificate(keyPair,textUserName.Text);

            // PINを設定
            if ( await setNewPIN(textPIN.Text) == false) {
                return;
            }

            // Authenticatorに書き込み
            {
                var writeDataList = createWriteDataList(encPrivatekey);

                addLog(string.Format($"Write-Start {writeDataList.Count}"));
                foreach (var rec in writeDataList) {
                    textLog.Text = textLog.Text + string.Format($"WrittengData...{rec.recno}");

                    var msg = await writeRec(GeboSigCommon.Common.RPID, textPIN.Text, rec);
                    msg = string.Format($"...{msg}") + "\r\n";
                    textLog.Text = textLog.Text + msg;
                }
                addLog(string.Format($"Write-End"));
            }

            // 証明書をエクスポート
            {
                string file = string.Format($@"{textCert.Text}{textUserName.Text}.crt");
                File.WriteAllText(file, cert);
            }

            addLog(string.Format($"Register-Success"));

            MessageBox.Show("登録が完了しました");

            return;
        }

        private async Task<bool> checkInput(bool checkPIN)
        {
            if( checkPIN)
            {
                var info = await gebo.CTAP2.WebAuthnModokiDesktop.Credentials.Info(gebo.CTAP2.DevParam.GetDefaultParams());
                if (info.isSuccess == false)
                {
                    addLog(string.Format($"Check Error ...{info.msg}"));
                    return false;
                }

                // PINが設定されていない状態でないといけない
                if (info.AuthenticatorInfo.Option_clientPin != gebo.CTAP2.CTAPResponseInfo.OptionFlag.present_and_set_to_false)
                {
                    addLog(string.Format($"Check Error ...Authenticatorを初期化してください"));
                    return false;
                }
            }

            return true;
        }

        private async Task<bool> setNewPIN(string pin)
        {
            var status = await gebo.CTAP2.WebAuthnModokiDesktop.Credentials.SetPin(gebo.CTAP2.DevParam.GetDefaultParams(), pin);
            if( status.isSuccess == false) {
                addLog(string.Format($"Set PIN Error ...{status.msg}"));
                return false;
            }

            return true;
        }

        private AsymmetricCipherKeyPair createKeyPair(int rsastrength)
        {
            // 鍵パラメータ作成
            var randGen = new CryptoApiRandomGenerator();
            var rand = new SecureRandom(randGen);
            var param = new KeyGenerationParameters(rand, rsastrength);

            // 鍵生成
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(param);
            var keyPair = keyGen.GenerateKeyPair();

            return (keyPair);
        }

        private string getPrivatekyPEM(AsymmetricCipherKeyPair keyPair)
        {
            var mem = new MemoryStream();
            using (var writer = new StreamWriter(mem, Encoding.ASCII)) {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(keyPair.Private);
                pemWriter.Writer.Flush();
            }
            var pem = Encoding.UTF8.GetString(mem.ToArray());

            return (pem);
        }

        private List<WriteData> createWriteDataList(byte[] derPrivatekey)
        {
            var fs = new MemoryStream(derPrivatekey);

            var writeDataList = new List<WriteData>();
            for (byte recno = 0; ; recno++) {
                var rec = new WriteData();

                // recno
                rec.recno = recno;

                {
                    byte[] bs = new byte[62];
                    int readSize = fs.Read(bs, 0, bs.Length);
                    if (readSize == 0) {
                        break;
                    }
                    rec.data1 = bs.ToList().Take(readSize).ToArray();
                }
                {
                    byte[] bs = new byte[32];
                    int readSize = fs.Read(bs, 0, bs.Length);
                    if (readSize == 0) {
                        writeDataList.Add(rec);
                        break;
                    }
                    rec.data2 = bs.ToList().Take(readSize).ToArray();
                }
                {
                    byte[] bs = new byte[32];
                    int readSize = fs.Read(bs, 0, bs.Length);
                    if (readSize == 0) {
                        writeDataList.Add(rec);
                        break;
                    }
                    rec.data3 = bs.ToList().Take(readSize).ToArray();
                }

                writeDataList.Add(rec);

            }
            fs.Close();

            return (writeDataList);
        }

        private async Task<string> writeRec(string rpid,string pin,WriteData rec)
        {
            string result = "";
            try {
                result = await Task<string>.Run(async () => {
                    byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

                    byte[] userid = new byte[] { rec.recno, rec.filler };
                    userid = userid.ToList().Concat(rec.data1).ToArray();

                    string username = (rec.data2 == null) ? "" : gebo.CTAP2.Common.BytesToHexString(rec.data2);
                    string userdisplayname = (rec.data3 == null) ? "" : gebo.CTAP2.Common.BytesToHexString(rec.data3);

                    string json =
                            "{" +
                                @"rp : {" +
                                    string.Format($"id : '{rpid}',") +
                                @"}," +
                                @"user : {" +
                                    string.Format($"id_bytearray:[{string.Join(",", userid)}],") +
                                    string.Format($"name :'{username}',") +
                                    string.Format($"displayName :'{userdisplayname}',") +
                                @"}," +
                                @"pubKeyCredParams: [{type: 'public-key',alg: -7}]," +
                                @"attestation: 'direct'," +
                                @"timeout: 60000," +
                                @"authenticatorSelection : {" +
                                    string.Format($"requireResidentKey : true,") +
                                    @"authenticatorAttachment : 'cross-platform'," +
                                    string.Format($"userVerification : 'discouraged'") +
                                @"}," +
                                string.Format($"challenge:[{string.Join(",", challenge)}],") +
                            "}";

                    var ret = await gebo.CTAP2.WebAuthnModokiDesktop.Credentials.Create(gebo.CTAP2.DevParam.GetDefaultParams(), json, pin);
                    if (ret.isSuccess == false) {
                        return ret.msg;
                    }
                    return ("Success");
                });

            } catch (Exception ex) {
                result = ex.Message;
            } finally {

            }
            return result;
        }

        private string createCertificate(AsymmetricCipherKeyPair keyPair,string username)
        {
            string commonname = string.Format($"{username}@{GeboSigCommon.Common.RPID}");

            // 証明書の属性
            var attr = new Dictionary<DerObjectIdentifier, string>()
            {
                { X509Name.CN, commonname },
                { X509Name.C, "Japan" },
                { X509Name.ST, "None" },
                { X509Name.L, "None" },
                { X509Name.O, "gebo" },
                { X509Name.OU, "None" },
            };
            var ord = new List<DerObjectIdentifier>()
            {
                X509Name.CN,
                X509Name.C,
                X509Name.ST,
                X509Name.L,
                X509Name.O,
                X509Name.OU,
            };

            // 証明書の生成
            var name = new X509Name(ord, attr);
            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigInteger.One);
            certGen.SetIssuerDN(name);
            certGen.SetSubjectDN(name);
            certGen.SetNotBefore(DateTime.Now);
            certGen.SetNotAfter(DateTime.Now.AddYears(10));
            certGen.SetPublicKey(keyPair.Public);
            var cert = certGen.Generate(new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, keyPair.Private));

            // 証明書の出力
            var mem = new MemoryStream();
            using (var writer = new StreamWriter(mem, Encoding.ASCII)) {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(cert);
                pemWriter.Writer.Flush();
            }
            var pem = Encoding.UTF8.GetString(mem.ToArray());

            return (pem);
        }

    }
}
