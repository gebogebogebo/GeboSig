using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GeboSigCommon
{
    public class Common
    {
        public static readonly string RPID = "GeboSig.gebo.com";

        public static readonly string SigAlgorithm = "SHA1withRSA";
        
        // DER から PEM に変換する
        public static string ConvertPrivateKeyDERtoPEM(byte[] der)
        {
            string pemdata = "-----BEGIN RSA PRIVATE KEY-----\n" + ConvertDERtoPEM(der) + "-----END RSA PRIVATE KEY-----\n";
            return pemdata;
        }
        private static string ConvertDERtoPEM(byte[] der)
        {
            // DER形式の証明書をPEM形式に変換する
            //     DER -> 鍵や証明書をASN.1というデータ構造で表し、それをシリアライズしたバイナリファイル
            //     PEM -> DERと同じASN.1のバイナリデータをBase64によってテキスト化されたファイル 
            // 1.Base64エンコード
            // 2.64文字ごとに改行コードをいれる
            // 3.ヘッダとフッタを入れる

            var b64cert = Convert.ToBase64String(der);

            string pemdata = "";
            int roopcount = (int)Math.Ceiling(b64cert.Length / 64.0f);
            for (int intIc = 0; intIc < roopcount; intIc++) {
                int start = 64 * intIc;
                if (intIc == roopcount - 1) {
                    pemdata = pemdata + b64cert.Substring(start) + "\n";
                } else {
                    pemdata = pemdata + b64cert.Substring(start, 64) + "\n";
                }
            }
            return pemdata;
        }

        // PEM から DER に変換する
        public static byte[] ConvertPEMtoDER(string pem)
        {
            var pems = pem.Trim('\n').Split('\n').ToList();

            // ヘッダとフッダは飛ばす
            pems.RemoveAt(0);
            pems.RemoveAt(pems.Count - 1);

            // つなげる
            var base64 = String.Join("", pems);

            // もどす
            return (Convert.FromBase64String(base64));
        }


        // ファイルのDigestInfoを作成する
        public static byte[] CreateSHA1DigestInfo(string targetFile)
        {

            byte[] digestSHA1 = null;
            using (var fs = new System.IO.FileStream(targetFile, System.IO.FileMode.Open, System.IO.FileAccess.Read)) {
                digestSHA1 = System.Security.Cryptography.SHA1.Create().ComputeHash(fs);
            }
            return (createDigestInfo(digestSHA1));
        }

        private static byte[] createDigestInfo(byte[] sigBaseSHA1)
        {
            // [ RFC 3447.PKCS #1.RSASSA-PKCS1-v1_5 ]

            // ASN.1 DigestInfo
            //DigestInfo::= SEQUENCE {
            //  SEQUENCE {
            //    OBJECT IDENTIFIER / SHA1(1,3,14,3,2,26)
            //    NULL
            //  }
            //  OCTET STRING digest
            //}

            // SEQUENCE
            var sequence = new List<byte>();
            // 01    : TAG             = SEQUENCE= 0x30             
            // 02    : Length of Value = length(OBJECT IDENTIFIER+NULL)             
            // 03-   : Value           = OBJECT IDENTIFIER+NULL
            {
                // <OBJECT IDENTIFIER>
                // 01    : TAG             = OID(OBJECT IDENTIFIER) = 0x06             
                // 02    : Length of Value = 5byte = 0x05             
                // 03-07 : Value           = 1,3,14,3,2,26 -> SHA1 = 0x2b 0e 03 02 1a 
                // http://www.geocities.co.jp/SiliconValley-SanJose/3377/asn1Body.html
                byte[] oid = new byte[] { 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a };

                // <NULL>
                // 01    : TAG             = NULL     = 0x05             
                // 02    : Length of Value = no Value = 0x00
                byte[] nl = new byte[] { 0x05, 0x00 };

                sequence.Add(0x30);
                sequence.Add((byte)(oid.Length + nl.Length));
                sequence.AddRange(oid.ToArray());
                sequence.AddRange(nl.ToArray());
            }

            // <OCTET STRING>
            // 01    : TAG             = OCTET STRING   = 0x04             
            // 02    : Length of Value = length(digest)
            // 03-   : Value           = digest
            var digest = new List<byte>();
            {
                digest.Add(0x04);
                digest.Add((byte)sigBaseSHA1.Length);
                digest.AddRange(sigBaseSHA1.ToArray());
            }

            // <DigestInfo>
            // 01    : TAG             = SEQUENCE= 0x30
            // 02    : Length of Value = length(SEQUENCE+digest)           
            // 03-   : Value           = SEQUENCE+digest
            var digestInfo = new List<byte>();
            {
                digestInfo.Add(0x30);
                digestInfo.Add((byte)(sequence.Count + digest.Count));
                digestInfo.AddRange(sequence);
                digestInfo.AddRange(digest);
            }

            return digestInfo.ToArray();
        }

    }
}
