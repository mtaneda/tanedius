using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

class Program {
    /// <summary>
    ///   メインメソッド
    /// </summary>
    /// <param name="args"></param>
    /// <example>tanedius.exe User-Name User-Password NAS-IP-Address Server [secret]</example>
    static void Main(string[] args) {
        RadiusClient rc;

        switch (args.Length) {
            case 5:
                rc = new RadiusClient(args[0], args[1], args[2], RadiusClient.AUTH_TYPE.CHAP, args[3], args[4], "");
                if (rc.Auth())
                    System.Console.WriteLine("認証成功");
                else
                    System.Console.WriteLine("認証失敗");
                break;
            case 6:
                rc = new RadiusClient(args[0], args[1], args[2], RadiusClient.AUTH_TYPE.PAP, args[3], args[4], args[5]);
                if (rc.Auth())
                    System.Console.WriteLine("認証成功");
                else
                    System.Console.WriteLine("認証失敗");
                break;
            default:
                break;
        }

        System.Console.ReadKey();
        System.Environment.Exit(0);
    }
}
