using System.Diagnostics;
using Microsoft.IO;

namespace TeensySwgeInspectorTools;

public class PcapFile
{
    private static RecyclableMemoryStreamManager _manager = new();

    public Stream BaseStream { get; }
    private readonly BinaryWriter _writer;

    public PcapFile(Stream stream)
    {
        BaseStream = stream;
        _writer = new BinaryWriter(stream);
    }

    public void WriteHeader()
    {
        _writer.Write((uint)0xa1b2c3d4); // PCAP magic number
        _writer.Write((ushort)2); // PCAP major version
        _writer.Write((ushort)4); // PCAP minor version
        _writer.Write((uint)0); // Reserved
        _writer.Write((uint)0); // Reserved
        _writer.Write((uint)0x0000ffff); // Max length of capture frame
        _writer.Write((uint)272); // Nordic BLE link type
    }

    public void WriteBlePacket(uint timestampSeconds, uint timestampUs, byte flags, byte channel, byte rssiNegative, int eventCount, int timeDelta,
        byte[] packet)
    {
        // map direction to pcap master/slave flag
        var oflags = (byte)1;
        if ((flags & 0x3) == 1)
            oflags |= 2;

        var payload = Payload(oflags, channel, rssiNegative, eventCount, timeDelta, packet);
        
        _writer.Write(timestampSeconds);
        _writer.Write(timestampUs);
        _writer.Write(payload.Length);
        _writer.Write(payload.Length);
        _writer.Write(payload);
    }

    private static byte[] Payload(byte oflags, byte channel, byte rssiNegative, int eventCount, int timeDelta, byte[] packet)
    {
        using var payloadData = _manager.GetStream();
        var bw = new BinaryWriter(payloadData);

        bw.Write((byte)10);
        bw.Write(oflags);
        bw.Write(channel);
        bw.Write(rssiNegative);
        bw.Write((ushort)(eventCount & 0xFFFF));
        bw.Write(timeDelta);
        bw.Write(packet);

        var packetSize = (int)payloadData.Position;
        if (packetSize > 255)
            packetSize = 255;

        using var payloadHeader = _manager.GetStream();
        bw = new BinaryWriter(payloadHeader);

        bw.Write((byte)0x04); // Board ID
        bw.Write((byte)6);
        bw.Write((byte)packetSize);
        bw.Write((byte)1);
        bw.Write((ushort)0);
        bw.Write((byte)0x06);
        bw.Write(payloadData.ToArray()[..packetSize]);

        return payloadHeader.ToArray();
    }
}

public enum PacketTag : byte
{
    Data = 0,
    MsgResetComplete = 0x40,
    MsgConnectRequest = 0x41,
    MsgConnectionEvent = 0x42,
    MsgConnParamUpdate = 0x43,
    MsgChanMapUpdate = 0x44,
    MsgLog = 0x50,
    MsgTerminate = 0x45,
    CmdReset = 0x80,
    CmdGetVersion = 0x81,
    CmdSniffChannel = 0x82,
}

public record PacketHeader(PacketTag Tag, ushort Length)
{
    public static PacketHeader Read(BinaryReader r) => new((PacketTag)r.ReadByte(), r.ReadUInt16());
}

public record RadioData(uint Timestamp, byte Channel, byte Flags, byte RssiNegative, uint AdvertisingAddress)
{
    public static RadioData Read(BinaryReader r)
    {
        var timestamp = r.ReadUInt32();
        var channel = r.ReadByte();
        var flags = r.ReadByte();
        var rssi = r.ReadByte();
        r.ReadByte(); // reserved
        var advertisingAddress = r.ReadUInt32();

        return new RadioData(timestamp, channel, flags, rssi, advertisingAddress);
    }
}

class Program
{
    public static void Main(string[] args)
    {
        using var pcapStream = File.OpenWrite("/home/cnewman/Desktop/0001.pcap");
        var pcap = new PcapFile(pcapStream);
        pcap.WriteHeader();

        using var fs = File.OpenRead("/home/cnewman/Desktop/0001.bin");
        var br = new BinaryReader(fs);

        var eventCount = 0;

        var prevTimestamp = 0u;
        var timestampShift = 0L;
        
        while (fs.Position < fs.Length)
        {
            var timestampMillis = br.ReadUInt32();
            
            var header = PacketHeader.Read(br);
            var radioData = RadioData.Read(br);

            fs.Seek(-12, SeekOrigin.Current);
            var packetData = br.ReadBytes(header.Length);

            // detect and correct 32-bit microsecond timer overflow (roughly every 1:11:35)
            if (prevTimestamp > radioData.Timestamp)
                timestampShift += uint.MaxValue;

            var tsSec = (uint)((timestampShift + radioData.Timestamp) / 1000000);
            var tsUsec = (uint)((timestampShift + radioData.Timestamp) % 1000000);

            prevTimestamp = radioData.Timestamp;
            
            pcap.WriteBlePacket(tsSec, tsUsec, radioData.Flags, radioData.Channel, radioData.RssiNegative, eventCount, 0, packetData[8..]);

            eventCount++;
        }
    }
}