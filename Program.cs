using PacketAnalysis;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SniffGetDataFromPacket
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string filePath = @"C:\Temp\Примеры\5037out.pcapng";

            byte[] data = File.ReadAllBytes(filePath);

            byte[] byteArray = new byte[] { /* packet byte array goes here */ };
            PacketAnalyzer analyzer = new PacketAnalyzer();
            List<Packet> packets = analyzer.AnalyzePackets(data);

            foreach (Packet packet in packets)
            {
                Console.WriteLine("Source Address: " + BitConverter.ToString(packet.SourceAddress));
                Console.WriteLine("Destination Address: " + BitConverter.ToString(packet.DestinationAddress));
                Console.WriteLine("PAN ID: " + BitConverter.ToString(packet.PanId));
                Console.WriteLine("RSSI: " + packet.Rssi);
                Console.WriteLine();
                
            }
            Console.ReadLine();
        }
    }
}
