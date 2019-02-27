using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace GeboSigCommon
{
    public class BouncyCastleRijndael
    {
        static byte[] key;
        static byte[] iv;
        static PaddedBufferedBlockCipher cipher;
        static ParametersWithIV parametersWithIV;

        static BouncyCastleRijndael()
        {
            // AES-128
            key = Encoding.UTF8.GetBytes("ygmh8zudlw5u0a9w");
            iv = Encoding.UTF8.GetBytes( "o10wi1q3x2f98cob");

            // Rijndael
            // Mode = CBC
            // BlockSize = 128bit
            // PaddingMode = Zero
            var cbcBlockCipher = new CbcBlockCipher(new RijndaelEngine(128));
            cipher = new PaddedBufferedBlockCipher(cbcBlockCipher, new ZeroBytePadding());
            parametersWithIV = new ParametersWithIV(new KeyParameter(key), iv);
        }

        /* AES-256
        static BouncyCastleRijndael()
        {
            // AES-256
            key = Encoding.UTF8.GetBytes("ygmh8zudlw5u0a9w4vc29whc4b8wuech");
            iv = Encoding.UTF8.GetBytes( "o10wi1q3x2f98cobfkyisnwy9s9wxop7");

            // Rijndael
            // Mode = CBC
            // BlockSize = 256bit
            // PaddingMode = Zero
            //var cbcBlockCipher = new CbcBlockCipher(new RijndaelEngine(256));
            cipher = new PaddedBufferedBlockCipher(cbcBlockCipher, new ZeroBytePadding());
            parametersWithIV = new ParametersWithIV(new KeyParameter(key), iv);
        }
        */

        public static byte[] Encrypt(byte[] inData)
        {
            cipher.Init(true, parametersWithIV);
            var bytes = new byte[cipher.GetOutputSize(inData.Length)];
            var length = cipher.ProcessBytes(inData, bytes, 0);
            cipher.DoFinal(bytes, length);

            return bytes;
        }

        public static byte[] Decrypt(byte[] inData)
        {
            cipher.Init(false, parametersWithIV);
            var bytes = new byte[cipher.GetOutputSize(inData.Length)];
            var length = cipher.ProcessBytes(inData, bytes, 0);
            var ret = cipher.DoFinal(bytes, length);

            //return bytes;
            var outData = new List<byte>();
            outData.AddRange(bytes);

            return outData.Take(length).ToArray();
        }
    }
}