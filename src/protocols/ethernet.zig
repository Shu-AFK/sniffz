const std = @import("std");

pub const EthernetFrame = struct {
    dst_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: u16,
    payload: []const u8,
};

pub const ParseError = error{TooShort};

pub fn parse(data: []const u8) ParseError!EthernetFrame {
    if (data.len < 14) return ParseError.TooShort;

    return EthernetFrame{
        .dst_mac = data[0..6].*,
        .src_mac = data[6..12].*,
        .ether_type = std.mem.readInt(u16, data[12..14], .big),
        .payload = data[14..],
    };
}
