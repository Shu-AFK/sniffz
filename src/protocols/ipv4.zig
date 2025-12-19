const std = @import("std");

pub const Protocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    unknown,

    pub fn from(val: u8) Protocol {
        return std.meta.intToEnum(Protocol, val) catch .unknown;
    }
};

pub const Ipv4Packet = struct {
    version: u4,
    ihl: u4,
    tos: u8,
    total_length: u16,
    identification: u16,
    flags: u3,
    fragment_offset: u13,
    ttl: u8,
    protocol: Protocol,
    checksum: u16,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    payload: []const u8,

    pub fn srcIpStr(self: Ipv4Packet, buf: *[15]u8) []const u8 {
        return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{
            self.src_ip[0],
            self.src_ip[1],
            self.src_ip[2],
            self.src_ip[3],
        }) catch unreachable;
    }

    pub fn dstIpStr(self: Ipv4Packet, buf: *[15]u8) []const u8 {
        return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{
            self.dst_ip[0],
            self.dst_ip[1],
            self.dst_ip[2],
            self.dst_ip[3],
        }) catch unreachable;
    }
};

pub const ParseError = error{
    TooShort,
    InvalidVersion,
    InvalidHeaderLength,
};

pub fn parse(data: []const u8) ParseError!Ipv4Packet {
    if (data.len < 20) return ParseError.TooShort;

    const version_ihl = data[0];
    const version: u4 = @intCast(version_ihl >> 4);
    const ihl: u4 = @intCast(version_ihl & 0x0F);

    if (version != 4) return ParseError.InvalidVersion;
    if (ihl < 5) return ParseError.InvalidHeaderLength;

    const header_len: usize = @as(usize, ihl) * 4;
    if (data.len < header_len) return ParseError.TooShort;

    const flags_frag = std.mem.readInt(u16, data[6..8], .big);
    const flags: u3 = @intCast(flags_frag >> 13);
    const fragment_offset: u13 = @intCast(flags_frag & 0x1FFF);

    return Ipv4Packet{
        .version = version,
        .ihl = ihl,
        .tos = data[1],
        .total_length = std.mem.readInt(u16, data[2..4], .big),
        .identification = std.mem.readInt(u16, data[4..6], .big),
        .flags = flags,
        .fragment_offset = fragment_offset,
        .ttl = data[8],
        .protocol = Protocol.from(data[9]),
        .checksum = std.mem.readInt(u16, data[10..12], .big),
        .src_ip = data[12..16].*,
        .dst_ip = data[16..20].*,
        .payload = data[header_len..],
    };
}
