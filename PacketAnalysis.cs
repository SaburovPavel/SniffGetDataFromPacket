using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace PacketAnalysis
{
    
    public class Packet
    {
        
        public byte[] SourceAddress { get; set; }
        public byte[] DestinationAddress { get; set; }
        public byte[] PanId { get; set; }
        public int Rssi { get; set; }
        public string IpSourceAddress { get; set; }
        public string IpDestinationAddress { get; set;}
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
                if (byteList[0] == packetStart61dc[0] && byteList[1] == packetStart61dc[1]) // если пакет начинается с 0x41, 0xd8 или c 0x61, 0xdc
                {
                    //var packetLength = GetPacketLength(byteList);                     
                    //(byteList[0] == packetStart41d8[0] && byteList[1] == packetStart41d8[1]) ||
                    //if (byteList[0] == packetStart41d8[0] && byteList[1] == packetStart41d8[1])
                    //{
                    //    var panAdress = GetAddress(byteList, 3, 2);
                    //    var destinationAddress = GetAddress(byteList, 5, 2);
                    //    var sourceAddress = GetAddress(byteList, 7, 8);
                    //    var ipdestinationAddress = ConvertToHexString(destinationAddress);
                    //    var ipsourceAddress = ConvertToHexString(sourceAddress);

                    //    var packet = new Packet
                    //    {
                    //        SourceAddress = sourceAddress,
                    //        DestinationAddress = destinationAddress,
                    //        PanId = panAdress,
                    //        IpDestinationAddress = ipdestinationAddress,
                    //        IpSourceAddress = ipsourceAddress
                    //        //Rssi = rssi
                    //    };

                    //    packets.Add(packet);
                    //}

                    var panAdress = GetAddress(byteList, 3, 2);
                    var destinationAddress = GetAddress(byteList, 5, 8);
                    var sourceAddress = GetAddress(byteList, 13, 8);
                    var ipdestinationAddress = ConvertToHexString(destinationAddress);
                    var ipsourceAddress = ConvertToHexString(sourceAddress);
                    int rssi = FindSequence(byteList.ToArray());
                    if (rssi > 0)
                    {
                        rssi = (sbyte)rssi;
                    }

                        var packet = new Packet
                        {
                            SourceAddress = sourceAddress,
                            DestinationAddress = destinationAddress,
                            PanId = panAdress,
                            IpDestinationAddress = ipdestinationAddress,
                            IpSourceAddress = ipsourceAddress,
                            Rssi = rssi
                        };

                    packets.Add(packet);


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
        public string ConvertToHexString(byte[] bytes)        {          

            StringBuilder hexString = new StringBuilder();
            foreach (byte b in bytes)
            {
                hexString.Append(b.ToString("X2")); // Используем "X2" для гарантированного формата с двумя символами
                hexString.Append(":");
            }
            
            hexString.Length -= 1; // Удаляем последний лишний символ ":"
            if (hexString.Length > 20)
            {
                hexString.Remove(0, 3);
                hexString.Insert(0, "02");
                hexString.Remove(hexString.Length - 3, 1);
                hexString.Remove(hexString.Length - 8, 1);
                hexString.Remove(hexString.Length - 13, 1);                
            }            

            return "::" + hexString.ToString().ToLower(); // Применяем ToLower() к результату
        }
        public int FindSequence(byte[] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                if (arr[i] == 255)
                {
                    if (i + 32 < arr.Length && IsSequenceInArray6(arr.Skip(i + 1).Take(32).ToArray()) && IsSequenceInArray7(arr.Skip(i + 1).Take(32).ToArray()))
                    {
                        return arr[i - 1];
                    }
                }
            }
            return 1;
        }
        private bool IsSequenceInArray6(byte[] arr)
        {
            for (int i = 0; i < arr.Length - 7; i++)
            {
                if (arr[i] == 0 && arr[i + 1] == 0 && arr[i + 2] == 0 && arr[i + 3] == 6 && arr[i + 4] == 0 && arr[i + 5] == 0 && arr[i + 6] == 0 )
                {
                    return true;
                }
            }
            return false;
        }
        private bool IsSequenceInArray7(byte[] arr)
        {
            for (int i = 0; i < arr.Length - 7; i++)
            {
                if (arr[i] == 0 && arr[i + 1] == 0 && arr[i + 2] == 0 && arr[i + 3] == 0 && arr[i + 4] == 0 && arr[i + 5] == 0 && arr[i + 6] == 0)
                {
                    return true;
                }
            }
            return false;
        }
        private sbyte GetRssi(byte[] packetData)
        {
            return (sbyte)packetData[packetData.Length - 1];
        }
    }
}
