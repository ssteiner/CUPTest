using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PresenceTester
{
    public class PresenceServerConfiguration
    {
        public string PrimaryAddress { get; set; }
        public string SecondaryAddress { get; set; }
        public string Login { get; set; }
        public string Password { get; set; }

        public bool UseHttp { get; set; }

        public int HttpsPort { get; private set; }
        public int HttpPort { get; private set; }

        public PresenceServerConfiguration()
        {
            HttpPort = 8082;
            HttpsPort = 8083;
        }
    }
}
