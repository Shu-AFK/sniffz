const std = @import("std");

pub const NextHeader = enum(u8) {
    hop_by_hop = 0,
    tcp = 6,
    udp = 17,
    ipv6_route = 43,
    ipv6_frag = 44,
    esp = 50,
    ah = 51,
    icmpv6 = 58,
    ipv6_no_next = 59,
    ipv6_opts = 60,
    _,

    pub fn from(val: u8) NextHeader {
        return @enumFromInt(val);
    }

    pub fn isExtensionHeader(self: NextHeader) bool {
        return switch (self) {
            .hop_by_hop, .ipv6_route, .ipv6_frag, .ah, .ipv6_opts => true,
            else => false,
        };
    }

    pub fn name(self: NextHeader) []const u8 {
        return switch (self) {
            .hop_by_hop => "Hop-by-Hop",
            .tcp => "TCP",
            .udp => "UDP",
            .ipv6_route => "Routing",
            .ipv6_frag => "Fragment",
            .esp => "ESP",
            .ah => "AH",
            .icmpv6 => "ICMPv6",
            .ipv6_no_next => "No Next",
            .ipv6_opts => "Dest Opts",
            _ => "Unknown",
        };
    }
};

pub const Ipv6Packet = struct {
    traffic_class: u8,
    flow_label: u20,
    payload_length: u16,
    next_header: NextHeader,
    hop_limit: u8,
    src: [16]u8,
    dst: [16]u8,
    payload: []const u8,

    pub fn srcIpStr(self: Ipv6Packet, buf: *[39]u8) []const u8 {
        return fmtIpv6(buf, self.src);
    }

    pub fn dstIpStr(self: Ipv6Packet, buf: *[39]u8) []const u8 {
        return fmtIpv6(buf, self.dst);
    }
};

pub const ParseError = error{ TooShort, BadVersion };

pub fn parse(data: []const u8) ParseError!Ipv6Packet {
    if (data.len < 40) return ParseError.TooShort;

    const v_tc_fl = std.mem.readInt(u32, data[0..4], .big);
    const version: u4 = @intCast(v_tc_fl >> 28);
    if (version != 6) return ParseError.BadVersion;

    const initial_nh = NextHeader.from(data[6]);
    const skip = skipExtensionHeaders(data[40..], initial_nh);

    return .{
        .traffic_class = @intCast((v_tc_fl >> 20) & 0xff),
        .flow_label = @intCast(v_tc_fl & 0x000f_ffff),
        .payload_length = std.mem.readInt(u16, data[4..6], .big),
        .next_header = skip.nh,
        .hop_limit = data[7],
        .src = data[8..24].*,
        .dst = data[24..40].*,
        .payload = data[40 + skip.offset ..],
    };
}

fn skipExtensionHeaders(data: []const u8, initial_nh: NextHeader) struct { nh: NextHeader, offset: usize } {
    var nh = initial_nh;
    var offset: usize = 0;

    while (nh.isExtensionHeader()) {
        if (offset + 2 > data.len) break;

        const next = NextHeader.from(data[offset]);
        // Fragment header is fixed 8 bytes, others use (len + 1) * 8
        const len: usize = if (nh == .ipv6_frag) 8 else (@as(usize, data[offset + 1]) + 1) * 8;

        offset += len;
        nh = next;
    }

    return .{ .nh = nh, .offset = offset };
}

fn fmtIpv6(buf: []u8, addr: [16]u8) []const u8 {
    if (isAllZero(addr)) return copyStr(buf, "::");
    if (isLoopback(addr)) return copyStr(buf, "::1");

    const h = readHextets(addr);
    const zr = longestZeroRun(h);

    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    var i: usize = 0;
    var need_colon = false;

    while (i < 8) {
        if (zr.len >= 2 and i == zr.start) {
            w.writeAll("::") catch unreachable;
            i += zr.len;
            need_colon = false;
            continue;
        }

        if (need_colon) w.writeByte(':') catch unreachable;
        w.print("{x}", .{h[i]}) catch unreachable;
        need_colon = true;
        i += 1;
    }

    return fbs.getWritten();
}

fn copyStr(buf: []u8, s: []const u8) []const u8 {
    @memcpy(buf[0..s.len], s);
    return buf[0..s.len];
}

fn isAllZero(a: [16]u8) bool {
    for (a) |b| if (b != 0) return false;
    return true;
}

fn isLoopback(a: [16]u8) bool {
    for (a[0..15]) |b| if (b != 0) return false;
    return a[15] == 1;
}

fn readHextets(addr: [16]u8) [8]u16 {
    var h: [8]u16 = undefined;
    for (0..8) |i| {
        h[i] = std.mem.readInt(u16, addr[i * 2 ..][0..2], .big);
    }
    return h;
}

const ZeroRun = struct { start: usize = 0, len: usize = 0 };

fn longestZeroRun(h: [8]u16) ZeroRun {
    var best = ZeroRun{};
    var i: usize = 0;

    while (i < 8) {
        if (h[i] != 0) {
            i += 1;
            continue;
        }

        const start = i;
        while (i < 8 and h[i] == 0) i += 1;

        if (i - start > best.len) {
            best = .{ .start = start, .len = i - start };
        }
    }

    return best;
}
