/**
 * tanedius
 * RadiusClient Class
 * Copyright (C) 2017 TANEDA M.
 * This code was designed and coded by TANEDA M.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;

/// <summary>
///   RADIUS クライアント
/// </summary>
class RadiusClient {

    /// <summary>
    ///   認証方式
    /// </summary>
    /// <note>
    ///   現時点では PAP, CHAP のみで MS-CHAP, EAP には対応しません
    /// </note>
    public enum AUTH_TYPE {PAP, CHAP};

    /// <summary>
    ///   コンストラクタ
    /// </summary>
    /// <param name="serverHost_">接続先ホスト</param>
    /// <param name="serverPort_">接続先ポート</param>
    /// <param name="userName_">ユーザ名</param>
    /// <param name="authType_">認証方式</param>
    /// <param name="userPassword_">パスワード</param>
    /// <param name="nasIpAddress_">NAS IP</param>
    /// <param name="secret_">共有鍵</param>
    /// <remarks>
    ///   <para>
    ///     共有鍵は PAP でのみ使います
    ///   </para>
    /// </remarks>
    public RadiusClient(string serverHost_,
                        string serverPort_,
                        string userName_,
                        AUTH_TYPE authType_,
                        string userPassword_,
                        string nasIpAddress_,
                        string secret_) {

        serverHost = serverHost_;
        serverPort = serverPort_;
        userName = userName_;
        authType = authType_;
        userPassword = userPassword_;
        nasIpAddress = nasIpAddress_;
        secret = secret_;

        request = new RadiusPacket();
        request.Code = RadiusPacket.CODE.ACCESS_REQUEST;
        request.AppendAttribute(new RadiusPacket.ValuePair(RadiusPacket.TYPE.USER_NAME, userName));
        switch (authType) {
            case AUTH_TYPE.PAP:
                request.SetSecret(secret);
                request.AppendAttribute(new RadiusPacket.ValuePair(RadiusPacket.TYPE.USER_PASSWORD, userPassword));
                break;
            case AUTH_TYPE.CHAP:
                request.AppendAttribute(new RadiusPacket.ValuePair(RadiusPacket.TYPE.CHAP_PASSWORD, userPassword));
                break;
        }
        request.AppendAttribute(new RadiusPacket.ValuePair(RadiusPacket.TYPE.NAS_IP_ADDRESS, nasIpAddress));
        request.BuildPacket();
    }

    /// <summary>
    ///   認証実行
    /// </summary>
    /// <returns>true 認証成功, false 認証失敗</returns>
    public bool Auth() {
        return auth();
    }

    /// <summary>
    ///   接続先ホスト
    /// </summary>
    private string serverHost;

    /// <summary>
    ///   接続先ポート
    /// </summary>
    private string serverPort;

    /// <summary>
    ///   ユーザ名
    /// </summary>
    private string userName;

    /// <summary>
    ///   認証方式
    /// </summary>
    private AUTH_TYPE authType;

    /// <summary>
    ///   パスワード
    /// </summary>
    private string userPassword;

    /// <summary>
    ///   NAS IP
    /// </summary>
    private string nasIpAddress;

    /// <summary>
    ///   共有鍵
    /// </summary>
    private string secret;

    /// <summary>
    ///   要求パケット
    /// </summary>
    private RadiusPacket request;

    /// <summary>
    ///   応答パケット
    /// </summary>
    private RadiusPacket reply;

    /// <summary>
    ///   認証実行
    /// </summary>
    /// <returns>true 認証成功, false 認証失敗</returns>
    private bool auth() {
        IPAddress[] addrList = Dns.GetHostAddresses(Dns.GetHostName());
        IPAddress addr = null;
        // 一番最初に見つかったIPv4アドレスを送信元とする
        // TODO: いろいろ変なので調整が必要
        foreach (IPAddress ipa in addrList) {
            if (ipa.AddressFamily == AddressFamily.InterNetwork) {
                addr = ipa;
                break;
            }
        }
        IPEndPoint local = new IPEndPoint(addr, (new Random((int)DateTime.Now.ToBinary())).Next(49152, 65535)); // TODO: 定数があれば使う
        UdpClient udp = new UdpClient(local);
        udp.Send(request.GetBuffer(), request.Length, serverHost, int.Parse(serverPort)); // TODO: int.Parse() は安全だっけ？
        IPEndPoint remote = null;
        byte[] rbuf = udp.Receive(ref remote);
        udp.Close();

        reply = new RadiusPacket(rbuf);

        if (request.PacketIdentifier == reply.PacketIdentifier)
            if (reply.Code == RadiusPacket.CODE.ACCESS_ACCEPT)
                return true;

        return false;
    }
}