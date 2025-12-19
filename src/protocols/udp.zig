const std = @import("std");

pub const UdpDatagram = struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    payload: []const u8,
};

pub const ParseError = error{TooShort};

pub fn parse(data: []const u8) ParseError!UdpDatagram {
    if (data.len < 8) return ParseError.TooShort;

    return UdpDatagram{
        .src_port = std.mem.readInt(u16, data[0..2], .big),
        .dst_port = std.mem.readInt(u16, data[2..4], .big),
        .length = std.mem.readInt(u16, data[4..6], .big),
        .checksum = std.mem.readInt(u16, data[6..8], .big),
        .payload = data[8..],
    };
}
