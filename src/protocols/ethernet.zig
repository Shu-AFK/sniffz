const std = @import("std");

pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86DD,
    vlan = 0x8100,
    unknown,

    pub fn from(val: u16) EtherType {
        return std.meta.intToEnum(EtherType, val) catch .unknown;
    }
};

pub const EthernetFrame = struct {
    dst_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: EtherType,
    ether_type_raw: u16,
    payload: []const u8,

    pub fn dstMacStr(self: EthernetFrame, buf: *[17]u8) []const u8 {
        return std.fmt.bufPrint(buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            self.dst_mac[0],
            self.dst_mac[1],
            self.dst_mac[2],
            self.dst_mac[3],
            self.dst_mac[4],
            self.dst_mac[5],
        }) catch unreachable;
    }

    pub fn srcMacStr(self: EthernetFrame, buf: *[17]u8) []const u8 {
        return std.fmt.bufPrint(buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            self.src_mac[0],
            self.src_mac[1],
            self.src_mac[2],
            self.src_mac[3],
            self.src_mac[4],
            self.src_mac[5],
        }) catch unreachable;
    }
};

pub const ParseError = error{TooShort};

pub fn parse(data: []const u8) ParseError!EthernetFrame {
    if (data.len < 14) return ParseError.TooShort;

    const raw_type = std.mem.readInt(u16, data[12..14], .big);

    return EthernetFrame{
        .dst_mac = data[0..6].*,
        .src_mac = data[6..12].*,
        .ether_type = EtherType.from(raw_type),
        .ether_type_raw = raw_type,
        .payload = data[14..],
    };
}
