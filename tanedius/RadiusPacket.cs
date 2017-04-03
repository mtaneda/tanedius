/**
 * tanedius
 * RadiusPacket Class
 * Copyright (C) 2017 TANEDA M.
 * This code was designed and coded by TANEDA M.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

/// <summary>
///   RADIUSパケット
/// </summary>
public class RadiusPacket {
#region enum
    /// <summary>
    ///   CODE
    /// </summary>
    public enum CODE {
        ACCESS_REQUEST = 1,
        ACCESS_ACCEPT = 2,
        ACCESS_REJECT = 3,
    }

    /// <summary>
    ///   Attribute Value Pairs のタイプ
    /// </summary>
    public enum TYPE {
        USER_NAME = 1,
        USER_PASSWORD = 2,
        CHAP_PASSWORD = 3,
        NAS_IP_ADDRESS = 4,
    }
        
#endregion
#region class
    /// <summary>
    ///   Attribute Value Pairs
    /// </summary>
    public class ValuePair {

        /// <summary>
        ///   コンストラクタ
        /// </summary>
        public ValuePair() {
            Type = 0;
            Value = "";
        }

        /// <summary>
        ///   コンストラクタ
        /// </summary>
        /// <param name="type_"></param>
        /// <param name="value_"></param>
        public ValuePair(TYPE type_, string value_) {
            Type = type_;
            Value = value_;
        }

        /// <summary>
        ///   Attribute Value Pairs のタイプ
        /// </summary>
        public TYPE Type {
            get { return type; }
            set { type = value; }
        }

        /// <summary>
        ///   Attribute Value Pairs の値
        /// </summary>
        public string Value {
            get { return this.value; }
            set { this.value = value; }
        }

        /// <summary>
        ///   Attribute Value Pairs のタイプ
        /// </summary>
        private TYPE type;

        /// <summary>
        ///   Attribute Value Pairs の値
        /// </summary>
        private string value;
    }
#endregion
#region property
    /// <summary>
    ///   CODE
    /// </summary>
    public CODE Code {
        get { return code; }
        set { code = value; }
    }

    /// <summary>
    ///   パケット識別子
    /// </summary>
    public byte PacketIdentifier {
        get { return packetIdentifier; }
    }

    /// <summary>
    ///   パケット長
    /// </summary>
    public int Length {
        get { return length; }
    }
    
    /// <summary>
    ///   Authenticator
    /// </summary>
    public byte[] Authenticator {
        get { return authenticator; }
        set { authenticator = value; }
    }
#endregion
#region methods

    /// <summary>
    ///   コンストラクタ
    /// </summary>
    /// <note>
    ///   パケットを組み立てるとき用
    /// </note>
    public RadiusPacket() {
        System.Random r = new System.Random((int)DateTime.Now.ToBinary());
        packetIdentifier = (byte)r.Next(255);
        authenticator = new byte[16];

        for (int i = 0; i < authenticator.Length; i++)
            authenticator[i] = (byte)r.Next(255);
    }

    /// <summary>
    ///   コンストラクタ
    /// </summary>
    /// <note>
    ///   パケットパース用
    /// </note>
    /// <param name="buf"></param>
    public RadiusPacket(byte[] buf) {
        if (buf.Length < 20)
            ; // TODO: エラー処理はどうしよう

        code = (CODE)buf[0];
        packetIdentifier = buf[1];
        length = (ushort)((buf[2] & 0x0f << 8) | buf[3] & 0xff);
        authenticator = new byte[16];
        Buffer.BlockCopy(buf, 4, authenticator, 0, authenticator.Length);
    }

    /// <summary>
    ///   パケット組み立て
    /// </summary>
    /// <note>
    ///   Attribute Value Pairs のことがあるので、
    ///   コンストラクト後、 SetSecret() や AppendAttribute() をしてからこれを呼んでください。
    /// </note>
    public void BuildPacket() {
        buildPacket();
    }
    
    /// <summary>
    ///   共有鍵をセットする
    /// </summary>
    /// <param name="secret_"></param>
    public void SetSecret(string secret_) {
        secret = System.Text.Encoding.ASCII.GetBytes(secret_);
    }


    /// <summary>
    ///   Attribute Value Pairs をセットする
    /// </summary>
    public void AppendAttribute(ValuePair vp) {
        if (attributeValuePairs == null) {
            attributeValuePairs = new List<ValuePair>();
        }

        attributeValuePairs.Add(vp);
    }

    /// <summary>
    ///   送信用パケットバッファを取得する
    /// </summary>
    /// <returns></returns>
    public byte[] GetBuffer() {
        return buffer;
    }

#endregion
#region private
    /// <summary>
    ///   CODE
    /// </summary>
    private CODE code;

    /// <summary>
    ///   パケット識別子
    /// </summary>
    private byte packetIdentifier;

    /// <summary>
    ///   パケット長
    /// </summary>
    private ushort length;

    /// <summary>
    ///   Authentictor
    /// </summary>
    private byte[] authenticator;

    /// <summary>
    ///   共有鍵
    /// </summary>
    private byte[] secret;

    /// <summary>
    ///   Attribute Value Pairs
    /// </summary>
    /// <note>
    ///   リスト構造です
    /// </note>
    private List<ValuePair> attributeValuePairs;
    
    /// <summary>
    ///   パケット組み立て用のバッファ
    /// </summary>
    private byte[] buffer;

    /// <summary>
    ///   パケット組み立て
    /// </summary>
    private void buildPacket() {
        if (buffer == null) {
            buffer = new byte[1500]; // MTUサイズあればいいだろう 
                                     // TODO: マジックナンバー廃止
        }

        int ptr = 0;
        buffer[ptr++] = (byte)Code;       // Access-Request などのコード
        buffer[ptr++] = packetIdentifier; // ランダムID
        buffer[ptr++] = 0;                
        buffer[ptr++] = 0;                // Length は未定
        // Authenticator をコピー
        Buffer.BlockCopy(authenticator, 0, buffer, ptr, authenticator.Length);
        ptr += authenticator.Length;
        // len(Code) + len(packetIdentifier) + len(Length) + len(authenticator)
        length = (ushort)(1 + 1 + 2 + authenticator.Length);

        // Attribute Value Pairs について type 特有の処理をする
        foreach (ValuePair vp in attributeValuePairs) {
            byte[] data = null;
            byte[] data2 = null;
            byte[] data3 = null;
            System.Security.Cryptography.MD5 md5;
            switch (vp.Type) {

                // USER_NAME はそのまま byte[] に変換するだけ
                case TYPE.USER_NAME:
                    data = System.Text.Encoding.ASCII.GetBytes(vp.Value);

                    buffer[ptr++] = (byte)vp.Type;
                    buffer[ptr++] = (byte)(data.Length + 2);
                    Buffer.BlockCopy(data, 0, buffer, ptr, data.Length);
                    ptr += data.Length;

                    length += (ushort)(data.Length + 2);
                    break;

                // PAP Password は暗号化する
                case TYPE.USER_PASSWORD:
                    data = System.Text.Encoding.ASCII.GetBytes(vp.Value);

                    // data を 16オクテットで割り切れる data2 に変換
                    int tmpLen = data.Length;
                    if ((tmpLen & 0x0f) != 0) {
                        tmpLen += 0x0f;
                        tmpLen &= ~0x0f;
                    }
                    data2 = new byte[tmpLen];
                    data2.Initialize();
                    Array.Copy(data, data2, data.Length);

                    // 共有鍵と Authenticator を連結したデータの MD5 を取得
                    byte[] c = new byte[secret.Length + authenticator.Length];
                    Array.Copy(secret, c, secret.Length);
                    Array.Copy(authenticator, 0, c, secret.Length, authenticator.Length);
                    md5 = System.Security.Cryptography.MD5.Create();
                    byte[] b = md5.ComputeHash(c);

                    // 16オクテット毎に USER_PASSWORD と xor を取得
                    for (int n = 0; n < tmpLen; n += 16) {
                        for (int i = 0; i < 16; i++) {
                            data2[i + n] ^= b[i];
                        }

                        data3 = new byte[secret.Length + 16];
                        Array.Copy(secret, c, secret.Length);
                        Array.Copy(data2,n, c, 0,authenticator.Length);
                        b = md5.ComputeHash(c);
                    }
                    md5.Clear();

                    buffer[ptr++] = (byte)vp.Type;
                    buffer[ptr++] = (byte)(data2.Length + 2);
                    Buffer.BlockCopy(data2, 0, buffer, ptr, data2.Length);
                    ptr += data2.Length;

                    length += (ushort)(data2.Length + 2);
                    break;
                    
                case TYPE.CHAP_PASSWORD:
                    data = System.Text.Encoding.ASCII.GetBytes(" " + vp.Value);
                    
                    data2 = new byte[data.Length + authenticator.Length];
                    Array.Copy(data, data2, data.Length);
                    Array.Copy(authenticator, 0, data2, data.Length, authenticator.Length);

                    md5 = System.Security.Cryptography.MD5.Create();
                    data2[0] = 1;
                    data3 = md5.ComputeHash(data2);
                    md5.Clear();

                    buffer[ptr++] = (byte)vp.Type;
                    buffer[ptr++] = (byte)(data3.Length + 3);
                    buffer[ptr++] = 1; // CHAP Indent 0x01
                    Buffer.BlockCopy(data3, 0, buffer, ptr, data3.Length);
                    ptr += data3.Length;

                    length += (ushort)(data3.Length + 3);
                    break;
                    
                case TYPE.NAS_IP_ADDRESS:
                    System.Net.IPAddress addr = System.Net.IPAddress.Parse(vp.Value);
                    data = addr.GetAddressBytes();

                    buffer[ptr++] = (byte)vp.Type;
                    buffer[ptr++] = (byte)(data.Length + 2);
                    Buffer.BlockCopy(data, 0, buffer, ptr, data.Length);
                    ptr += data.Length;

                    length += (ushort)(data.Length + 2);
                    break;
                    
                default:
                    break;
            }
        }

        // Length
        buffer[2] = (byte)((length & 0xff00)>>8);
        buffer[3] = (byte)((length & 0x00ff));
    }
#endregion
}
