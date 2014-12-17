using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PresenceTester
{
    class Program
    {
        static void Main(string[] args)
        {
            PresenceServerConfiguration config = new PresenceServerConfiguration 
            { 
                Login = "app user login", 
                Password = "app user password", 
                PrimaryAddress = "cup.host.here", 
                UseHttp = true 
            };

            PresenceConnector conn = new PresenceConnector(config);
            conn.Init();

            //if (conn.StartTest2())
            //{
            //    Console.WriteLine("Press enter to exit");
            //    Console.ReadLine();
            //    conn.EndTest2();
            //}

            conn.Test();
        }
    }
}
