namespace SIRCrypt
{
    using System;
    using System.IO;
    using System.Security.Cryptography.Xml;
    using System.Text;
    using System.Xml;

    public class XMLCanonicalizer
    {
        private byte[] XMLCanonicalizerResult;
        public string XMLContent;

        public bool C14NExc()
        {
            try
            {
                XmlDocument document = new XmlDocument {
                    PreserveWhitespace = false
                };
                document.LoadXml(this.XMLContent);
                MemoryStream output = new MemoryStream();
                XmlWriter w = XmlWriter.Create(output);
                document.WriteTo(w);
                w.Flush();
                output.Position = 0L;
                XmlDsigExcC14NTransform transform = new XmlDsigExcC14NTransform();
                transform.LoadInput(output);
                this.XMLCanonicalizerResult = ((MemoryStream) transform.GetOutput(typeof(Stream))).ToArray();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public string CanonicalXML
        {
            get
            {
                return Encoding.UTF8.GetString(this.XMLCanonicalizerResult);
            }
        }
    }
}

