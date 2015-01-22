using System;
using System.IO;
using System.IO.Pipes;
using System.Collections.Generic;
using System.Security.Principal;

using Peach.Core.IO;
using NLog;

namespace Peach.Core.Publishers
{
    [Publisher("NamedPipe", true)]
    [Parameter("host", typeof(string), "Hostname or IP address of remote host")]
    [Parameter("pipeName", typeof(string), "Pipe name")]
    [Parameter("impersonationLevel", typeof(int), "Impersonation level")]

    public class NamedPipePublisher : StreamPublisher
    {
        private NamedPipeClientStream pipeClient;
        private string  host { get; set; }
        private string pipeName { get; set; }
        private int impersonationLevel { get; set; }
        private static NLog.Logger logger = LogManager.GetCurrentClassLogger();
        protected override NLog.Logger Logger { get { return logger; } }

        public NamedPipePublisher(Dictionary<string, Variant> args) : base(args)
        {
            pipeClient = new NamedPipeClientStream(host, pipeName, PipeDirection.Out, PipeOptions.None, (TokenImpersonationLevel)impersonationLevel);
            pipeClient.Connect();
        }

        ~NamedPipePublisher()
        {
            pipeClient.Close();
        }

		protected override void OnOpen()
        {
        }

		protected override void OnClose()
		{
		}

		protected override void OnOutput(BitwiseStream data)
		{
            BinaryReader br = new BinaryReader(data);
            int len = (int)data.Length;
            byte[] buffer;

            buffer = br.ReadBytes(len);
            try {
                pipeClient.Write(buffer, 0, len);
            }
            catch(IOException) {
                logger.Fatal("Named pipe server was closed");
                // Console.WriteLine("Named pipe server was closed");
            }
		}
    }
}
