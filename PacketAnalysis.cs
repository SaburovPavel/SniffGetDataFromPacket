using System;
using System.Collections.Generic;
using System.Linq;

namespace PacketAnalysis
{
    
    public class Packet
    {
        
        public byte[] SourceAddress { get; set; }
        public byte[] DestinationAddress { get; set; }
        public byte[] PanId { get; set; }
        public byte[] Rssi { get; set; }
    }

    public class PacketAnalyzer
    {
        public byte[] packetStart41d8 = new byte[] { 0x41, 0xd8 };
        public byte[] packetStart61dc = new byte[] { 0x61, 0xdc };
        public List<Packet> AnalyzePackets(byte[] byteArray)
        {
            var packets = new List<Packet>();
            var byteList = byteArray.ToList();

            while (byteList.Count > 0)
            {
                if ((byteList[0] == packetStart41d8[0] && byteList[1] == packetStart41d8[1]) 
                    || (byteList[0] == packetStart61dc[0] && byteList[1] == packetStart61dc[1])) // если пакет начинается с 0x41, 0xd8 или c 0x61, 0xdc
                {
                    //var packetLength = GetPacketLength(byteList);                     

                    if (byteList[0] == packetStart41d8[0] && byteList[1] == packetStart41d8[1])
                    {
                        var panAdress = GetAddress(byteList, 3, 2);
                        var destinationAddress = GetAddress(byteList, 5, 2);
                        var sourceAddress = GetAddress(byteList, 7, 8);

                        var packet = new Packet
                        {
                            SourceAddress = sourceAddress,
                            DestinationAddress = destinationAddress,
                            PanId = panAdress,
                            //Rssi = rssi
                        };

                        packets.Add(packet);
                    }
                    else if (byteList[0] == packetStart61dc[0] && byteList[1] == packetStart61dc[1])
                    {
                        var panAdress = GetAddress(byteList, 3, 2);
                        var destinationAddress = GetAddress(byteList, 5, 8);
                        var sourceAddress = GetAddress(byteList, 13, 8);

                        var packet = new Packet
                        {
                            SourceAddress = sourceAddress,
                            DestinationAddress = destinationAddress,
                            PanId = panAdress,
                            //Rssi = rssi
                        };

                        packets.Add(packet);
                    }
                    

                    //if (byteList.Count >= packetLength)
                    //{
                    //    var packetData = byteList.Take(packetLength).ToArray();
                    //    byteList = byteList.Skip(packetLength).ToList();

                    //    var sourceAddress = Get6LowPANAddress(packetData, 12, 8);
                    //    var destinationAddress = Get6LowPANAddress(packetData, 20, 8);
                    //    var panId = GetPanId(packetData, 28);
                    //    var rssi = GetRssi(packetData);

                    
                    byteList.RemoveAt(0);
                    //}
                    //else
                    //{
                    //    break;
                    //}
                }
                else
                {
                    byteList.RemoveAt(0);
                }
            }

            return packets;
        }
        
        static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                    return false;
            }

            return true;
        }

        //private ushort GetPacketLength(byte[] lengthBytes)
        //{
        //    int count = 0;
        //    byte[] packetEnd = new byte[] { 0x41, 0xff };
        //    byte[] packetEnd = new byte[] { 0x41, 0xd8 };
        //}

        private byte[] GetAddress(List<byte> packetData, int skip, int take)
        {
            return packetData.Skip(skip).Take(take).ToArray().Reverse().ToArray();
        }       

        private sbyte GetRssi(byte[] packetData)
        {
            return (sbyte)packetData[packetData.Length - 1];
        }
    }
}
