using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

class Program {
    /// <summary>
    ///   メインメソッド
    /// </summary>
    /// <param name="args"></param>
    /// <example>tanedius.exe User-Name Chap-Password NAS-IP-Address Server</example>
    static void Main(string[] args) {
        RadiusClient rc = new RadiusClient("192.168.134.145", "1812", "ccaaddccaadd", RadiusClient.AUTH_TYPE.CHAP, "ccaaddccaadd", "192.168.134.129");
        rc.Auth();
        System.Console.ReadLine();
    }
}
