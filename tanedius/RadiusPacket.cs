using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

/// <summary>
/// 
/// </summary>
public class RadiusPacket {
#region enum
    /// <summary>
    /// 
    /// </summary>
    public enum CODE {
        ACCESS_REQUEST = 1,
    }

    /// <summary>
    /// 
    /// </summary>
    public enum TYPE {
        USER_NAME = 1,
        CHAP_PASSWORD = 3,
        NAS_IP_ADDRESS = 4,
    }
        
#endregion
#region class
    /// <summary>
    /// 
    /// </summary>
    public class ValuePair {

        /// <summary>
        /// 
        /// </summary>
        public ValuePair() {
            Type = 0;
            Length = 0;
            Value = "";
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="type_"></param>
        /// <param name="value_"></param>
        public ValuePair(TYPE type_, string value_) {
            Type = type_;
            Value = value_;
        }

        /// <summary>
        /// 
        /// </summary>
        public TYPE Type {
            get { return type; }
            set { type = value; }
        }

        /// <summary>
        /// 
        /// </summary>
        public byte Length {
            get { return length; }
            set { length = value; }
        }

        /// <summary>
        /// 
        /// </summary>
        public string Value {
            get { return this.value; }
            set { this.value = value; }
        }

        /// <summary>
        /// 
        /// </summary>
        private TYPE type;

        /// <summary>
        /// 
        /// </summary>
        private byte length;

        /// <summary>
        /// 
        /// </summary>
        private string value;
    }
#endregion
#region property
    /// <summary>
    /// 
    /// </summary>
    public CODE Code {
        get { return code; }
        set { code = value; }
    }

    /// <summary>
    /// 
    /// </summary>
    public byte PacketIdentifier {
        get { return packetIdentifier; }
    }

    /// <summary>
    /// 
    /// </summary>
    public ushort Length {
        get { return length; }
    }

    /// <summary>
    /// 
    /// </summary>
    public byte[] Authenticator {
        get { return authenticator; }
        set { authenticator = value; }
    }
#endregion
#region methods

    /// <summary>
    /// 
    /// </summary>
    public RadiusPacket() {
        System.Random r = new System.Random((int)DateTime.Now.ToBinary());
        //packetIdentifier = (byte)r.Next(255);
        packetIdentifier = 1;
        authenticator = new byte[16];
    }

    /// <summary>
    /// 
    /// </summary>
    public void BuildPacket() {
        buildPacket();
    }

    /// <summary>
    /// 
    /// </summary>
    public void AppendAttribute(ValuePair vp) {
        if (attributeValuePairs == null) {
            attributeValuePairs = new List<ValuePair>();
        }

        attributeValuePairs.Add(vp);
    }

    public byte[] GetBuffer() {
        return buffer;
    }

#endregion
#region private
    /// <summary>
    /// 
    /// </summary>
    private CODE code;

    /// <summary>
    /// 
    /// </summary>
    private byte packetIdentifier;

    /// <summary>
    /// 
    /// </summary>
    private ushort length;

    /// <summary>
    /// 
    /// </summary>
    private byte[] authenticator;

    /// <summary>
    /// 
    /// </summary>
    private List<ValuePair> attributeValuePairs;

    /// <summary>
    /// 
    /// </summary>
    private byte[] buffer;

    /// <summary>
    /// 
    /// </summary>
    private void buildPacket() {
        if (buffer == null) {
            buffer = new byte[1500]; // MTUサイズあればいいだろう 
                                     // TODO: マジックナンバー廃止
        }

        int ptr = 0;
        buffer[ptr++] = (byte)Code;
        buffer[ptr++] = packetIdentifier;
        buffer[ptr++] = 0;
        buffer[ptr++] = 0;
        Buffer.BlockCopy(authenticator, 0, buffer, ptr, authenticator.Length);
        ptr += authenticator.Length;
        length = (ushort)(1 + 1 + 2 + authenticator.Length);

        foreach (ValuePair vp in attributeValuePairs) {
            byte[] data = null;
            switch (vp.Type) {
                case TYPE.USER_NAME:
                    data = System.Text.Encoding.ASCII.GetBytes(vp.Value);

                    buffer[ptr++] = (byte)vp.Type;
                    buffer[ptr++] = (byte)(data.Length + 2);
                    Buffer.BlockCopy(data, 0, buffer, ptr, data.Length);
                    ptr += data.Length;

                    vp.Length = (byte)data.Length; // これはいらなかった

                    length += (ushort)(data.Length + 2);
                    System.Console.WriteLine("Length = {0}", length);
                    break;
                case TYPE.CHAP_PASSWORD:
                    data = System.Text.Encoding.ASCII.GetBytes(" " + vp.Value);
                    byte[] data2 = new byte[data.Length + authenticator.Length];
                    Array.Copy(data, data2, data.Length);
                    Array.Copy(authenticator, 0, data2, data.Length, authenticator.Length);

                    System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create();
                    data2[0] = 1;
                    byte[] data3 = md5.ComputeHash(data2);
                    md5.Clear();

                    buffer[ptr++] = (byte)vp.Type;
                    buffer[ptr++] = (byte)(data3.Length + 3);
                    buffer[ptr++] = 1; // CHAP Indent 0x01
                    Buffer.BlockCopy(data3, 0, buffer, ptr, data3.Length);
                    ptr += data3.Length;

                    vp.Length = (byte)data3.Length; // これはいらなかった

                    length += (ushort)(data3.Length + 3);
                    System.Console.WriteLine("Length = {0}", length);
                    break;
                case TYPE.NAS_IP_ADDRESS:
                    System.Net.IPAddress addr = System.Net.IPAddress.Parse(vp.Value);
                    data = addr.GetAddressBytes();

                    buffer[ptr++] = (byte)vp.Type;
                    buffer[ptr++] = (byte)(data.Length + 2);
                    Buffer.BlockCopy(data, 0, buffer, ptr, data.Length);
                    ptr += data.Length;

                    vp.Length = (byte)data.Length; // これはいらなかった

                    length += (ushort)(data.Length + 2);
                    System.Console.WriteLine("Length = {0}", length);
                    break;
                default:
                    break;
            }
        }

        buffer[2] = (byte)((length & 0xff00)>>8);
        buffer[3] = (byte)((length & 0x00ff));
    }
#endregion
}
