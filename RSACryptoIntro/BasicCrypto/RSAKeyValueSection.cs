using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;

namespace eip.dl.util
{
    public class RSAKeyValueSection : ConfigurationSection
    {
        [ConfigurationProperty("Modulus")]
        public RSAKeyValueElement Modulus
        {
            get { return this["Modulus"] as RSAKeyValueElement; }
            set { this["Modulus"] = value; }
        }

        [ConfigurationProperty("Exponent")]
        public RSAKeyValueElement Exponent
        {
            get { return this["Exponent"] as RSAKeyValueElement; }
            set { this["Exponent"] = value; }
        }

        [ConfigurationProperty("P")]
        public RSAKeyValueElement P
        {
            get { return this["P"] as RSAKeyValueElement; }
            set { this["P"] = value; }
        }

        [ConfigurationProperty("Q")]
        public RSAKeyValueElement Q
        {
            get { return this["Q"] as RSAKeyValueElement; }
            set { this["Q"] = value; }
        }

        [ConfigurationProperty("DP")]
        public RSAKeyValueElement DP
        {
            get { return this["DP"] as RSAKeyValueElement; }
            set { this["DP"] = value; }
        }

        [ConfigurationProperty("DQ")]
        public RSAKeyValueElement DQ
        {
            get { return this["DQ"] as RSAKeyValueElement; }
            set { this["DQ"] = value; }
        }

        [ConfigurationProperty("InverseQ")]
        public RSAKeyValueElement InverseQ
        {
            get { return this["InverseQ"] as RSAKeyValueElement; }
            set { this["InverseQ"] = value; }
        }

        [ConfigurationProperty("D")]
        public RSAKeyValueElement D
        {
            get { return this["D"] as RSAKeyValueElement; }
            set { this["D"] = value; }
        }
        public RSAParameters CreateRSAParametersFromConfig( bool inclPrivate = true)
        {
            RSAParameters answer = new RSAParameters();

            answer.Modulus = Convert.FromBase64String(this.Modulus.InnerText);
            answer.Exponent = Convert.FromBase64String(this.Exponent.InnerText);

            if (inclPrivate)
            {
                answer.P = Convert.FromBase64String(this.P.InnerText);
                answer.Q = Convert.FromBase64String(this.Q.InnerText);
                answer.DP = Convert.FromBase64String(this.DP.InnerText);
                answer.DQ = Convert.FromBase64String(this.DQ.InnerText);
                answer.InverseQ = Convert.FromBase64String(this.InverseQ.InnerText);
                answer.D = Convert.FromBase64String(this.D.InnerText);
            }

            return answer;
        }
    }
}
