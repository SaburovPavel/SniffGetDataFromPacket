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
            string filePath = @"C:\Temp\Примеры\2эт 816 на 2эт.pcapng";

            byte[] data = File.ReadAllBytes(filePath);

            byte[] byteArray = new byte[] { /* packet byte array goes here */ };
            PacketAnalyzer analyzer = new PacketAnalyzer();
            List<Packet> packets = analyzer.AnalyzePackets(data);
            int count = 1;
            foreach (Packet packet in packets)
            {
                Console.WriteLine(count.ToString() + " " + "PAN ID: " + BitConverter.ToString(packet.PanId));
                Console.WriteLine("Destination Address: " + BitConverter.ToString(packet.DestinationAddress));
                Console.WriteLine("Source Address: " + BitConverter.ToString(packet.SourceAddress));                
                Console.WriteLine($"RSSI: {packet.Rssi}");
                Console.WriteLine("IP Destination: " + packet.IpDestinationAddress);
                Console.WriteLine("IP Source: " + packet.IpSourceAddress);
                Console.WriteLine();
                count ++;


            }
            Console.ReadLine();
        }
    }
}
