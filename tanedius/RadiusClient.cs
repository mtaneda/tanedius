using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

/// <summary>
/// 
/// </summary>
class RadiusClient {

    /// <summary>
    /// 
    /// </summary>
    public enum AUTH_TYPE {PAP, CHAP};

    /// <summary>
    /// 
    /// </summary>
    /// <param name="serverHost_"></param>
    /// <param name="serverPort_"></param>
    /// <param name="userName_"></param>
    /// <param name="authType_"></param>
    /// <param name="userPassword_"></param>
    /// <param name="nasIpAddress_"></param>
    public RadiusClient(string serverHost_,
                        string serverPort_,
                        string userName_,
                        AUTH_TYPE authType_,
                        string userPassword_,
                        string nasIpAddress_) {

        serverHost = serverHost_;
        serverPort = serverPort_;
        userName = userName_;
        authType = authType_;
        userPassword = userPassword_;
        nasIpAddress = nasIpAddress_;

        rp = new RadiusPacket();

        rp.Code = RadiusPacket.CODE.ACCESS_REQUEST;
        rp.AppendAttribute(new RadiusPacket.ValuePair(RadiusPacket.TYPE.USER_NAME, userName));
        rp.AppendAttribute(new RadiusPacket.ValuePair(RadiusPacket.TYPE.CHAP_PASSWORD, userPassword));
        rp.AppendAttribute(new RadiusPacket.ValuePair(RadiusPacket.TYPE.NAS_IP_ADDRESS, nasIpAddress));

        rp.BuildPacket();
    }

    /// <summary>
    /// 
    /// </summary>
    public void Auth() {
        string localIpString = "192.168.134.129";
        System.Net.IPAddress localAddress = System.Net.IPAddress.Parse(localIpString);
        int localPort = 35000;
        System.Net.IPEndPoint localEP = new System.Net.IPEndPoint(localAddress, localPort);
        System.Net.Sockets.UdpClient udp = new System.Net.Sockets.UdpClient(localEP);
        udp.Send(rp.GetBuffer(), rp.Length, serverHost, int.Parse(serverPort));
        System.Net.IPEndPoint remoteEP = null;
        byte[] rcvBytes = udp.Receive(ref remoteEP);
        udp.Close();
    }


    /// <summary>
    /// 
    /// </summary>
    private string serverHost;

    /// <summary>
    /// 
    /// </summary>
    private string serverPort;

    /// <summary>
    /// 
    /// </summary>
    private string userName;

    /// <summary>
    /// 
    /// </summary>
    private AUTH_TYPE authType;

    /// <summary>
    /// 
    /// </summary>
    private string userPassword;

    /// <summary>
    /// 
    /// </summary>
    private string nasIpAddress;

    /// <summary>
    /// 
    /// </summary>
    private RadiusPacket rp;

}