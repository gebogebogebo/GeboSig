using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GeboSigCommon
{
    public class WriteData
    {
        public byte recno = 0x00;
        public byte filler = 0xFF;
        public byte[] data1;
        public byte[] data2;
        public byte[] data3;

        public WriteData()
        {
        }

        public WriteData(byte[] userId, string userName, string userDisplayName)
        {
            recno = 0x00;
            filler = 0xFF;
            if (userId == null || userId.Length < 2) {
                return;
            }
            recno = userId[0];
            //recno[1] = userId[1];
            data1 = userId.ToList().Skip(2).ToArray();

            if (userName != null) {
                data2 = gebo.CTAP2.Common.HexStringToBytes(userName);
            }
            if (userDisplayName != null) {
                data3 = gebo.CTAP2.Common.HexStringToBytes(userDisplayName);
            }
        }
    }
}
