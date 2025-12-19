const std = @import("std");

pub const Flags = struct {
    fin: bool,
    syn: bool,
    rst: bool,
    psh: bool,
    ack: bool,
    urg: bool,
    ece: bool,
    cwr: bool,

    pub fn from(val: u8) Flags {
        return Flags{
            .fin = (val & 0x01) != 0,
            .syn = (val & 0x02) != 0,
            .rst = (val & 0x04) != 0,
            .psh = (val & 0x08) != 0,
            .ack = (val & 0x10) != 0,
            .urg = (val & 0x20) != 0,
            .ece = (val & 0x40) != 0,
            .cwr = (val & 0x80) != 0,
        };
    }

    pub fn format(self: Flags, buf: *[8]u8) []const u8 {
        var len: usize = 0;
        if (self.syn) {
            buf[len] = 'S';
            len += 1;
        }
        if (self.ack) {
            buf[len] = 'A';
            len += 1;
        }
        if (self.fin) {
            buf[len] = 'F';
            len += 1;
        }
        if (self.rst) {
            buf[len] = 'R';
            len += 1;
        }
        if (self.psh) {
            buf[len] = 'P';
            len += 1;
        }
        if (self.urg) {
            buf[len] = 'U';
            len += 1;
        }
        if (self.ece) {
            buf[len] = 'E';
            len += 1;
        }
        if (self.cwr) {
            buf[len] = 'C';
            len += 1;
        }
        return buf[0..len];
    }
};

pub const TcpSegment = struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset: u4,
    flags: Flags,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
    payload: []const u8,
};

pub const ParseError = error{
    TooShort,
    InvalidDataOffset,
};

pub fn parse(data: []const u8) ParseError!TcpSegment {
    if (data.len < 20) return ParseError.TooShort;

    const data_offset: u4 = @intCast(data[12] >> 4);
    if (data_offset < 5) return ParseError.InvalidDataOffset;

    const header_len: usize = @as(usize, data_offset) * 4;
    if (data.len < header_len) return ParseError.TooShort;

    return TcpSegment{
        .src_port = std.mem.readInt(u16, data[0..2], .big),
        .dst_port = std.mem.readInt(u16, data[2..4], .big),
        .seq_num = std.mem.readInt(u32, data[4..8], .big),
        .ack_num = std.mem.readInt(u32, data[8..12], .big),
        .data_offset = data_offset,
        .flags = Flags.from(data[13]),
        .window = std.mem.readInt(u16, data[14..16], .big),
        .checksum = std.mem.readInt(u16, data[16..18], .big),
        .urgent_ptr = std.mem.readInt(u16, data[18..20], .big),
        .payload = data[header_len..],
    };
}
