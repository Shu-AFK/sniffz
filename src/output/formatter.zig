const std = @import("std");
const packet = @import("../protocols/packet.zig");
const hexdump = @import("hexdump.zig");

pub const fflags = struct {
    verbose: bool,
    hexdump: bool,
};

fn formatIcmpLine(writer: anytype, src_ip: []const u8, dst_ip: []const u8, ic: anytype) !void {
    const proto_name: []const u8 = switch (ic) {
        .v4 => "ICMP",
        .v6 => "ICMPv6",
    };

    const type_name = ic.typeName();
    const code_name = ic.codeName();

    if (!std.mem.eql(u8, type_name, "Unknown")) {
        try writer.print("{s} -> {s} {s} {s}", .{ src_ip, dst_ip, proto_name, type_name });

        if (code_name.len != 0) {
            try writer.print(" ({s})", .{code_name});
        }

        switch (ic) {
            .v4 => |p4| {
                switch (p4.type) {
                    .echo_request, .echo_reply => {
                        const id = std.mem.readInt(u16, p4.rest[0..2], .big);
                        const seq = std.mem.readInt(u16, p4.rest[2..4], .big);
                        try writer.print(" id=0x{x:0>4} seq={d}", .{ id, seq });
                    },
                    else => {},
                }
                try writer.print(" len={d}\n", .{p4.payload.len});
            },
            .v6 => |p6| {
                switch (p6.type) {
                    .echo_request, .echo_reply => {
                        const id = std.mem.readInt(u16, p6.rest[0..2], .big);
                        const seq = std.mem.readInt(u16, p6.rest[2..4], .big);
                        try writer.print(" id=0x{x:0>4} seq={d}", .{ id, seq });
                    },
                    else => {},
                }
                try writer.print(" len={d}\n", .{p6.payload.len});
            },
        }
        return;
    }

    const tc = ic.typeCode();
    const payload_len: usize = switch (ic) {
        .v4 => |p4| p4.payload.len,
        .v6 => |p6| p6.payload.len,
    };

    try writer.print("{s} -> {s} {s} type={d} code={d} len={d}\n", .{
        src_ip, dst_ip, proto_name, tc.type, tc.code, payload_len,
    });
}

pub fn format(writer: anytype, index: usize, pkt: packet.DecodedPacket, raw: []const u8, flags: fflags) !void {
    try writer.print("#{d:<4} ", .{index});

    if (flags.verbose) {
        if (pkt.ethernet) |eth| {
            var src_buf: [17]u8 = undefined;
            var dst_buf: [17]u8 = undefined;
            try writer.print("{s} -> {s} ", .{
                eth.srcMacStr(&src_buf),
                eth.dstMacStr(&dst_buf),
            });
        }
    }

    if (pkt.ipv4) |ip| {
        var src_buf: [15]u8 = undefined;
        var dst_buf: [15]u8 = undefined;
        const src_ip = ip.srcIpStr(&src_buf);
        const dst_ip = ip.dstIpStr(&dst_buf);

        if (pkt.tcp) |t| {
            var flags_buf: [8]u8 = undefined;
            try writer.print("{s}:{d} -> {s}:{d} TCP [{s}] len={d}\n", .{
                src_ip, t.src_port, dst_ip, t.dst_port, t.flags.format(&flags_buf), t.payload.len,
            });
        } else if (pkt.udp) |u| {
            try writer.print("{s}:{d} -> {s}:{d} UDP len={d}\n", .{
                src_ip, u.src_port, dst_ip, u.dst_port, u.payload.len,
            });
        } else if (pkt.icmp) |ic| {
            try formatIcmpLine(writer, src_ip, dst_ip, ic);
        } else {
            try writer.print("{s} -> {s} {s}\n", .{
                src_ip, dst_ip, @tagName(ip.protocol),
            });
        }
    } else if (pkt.ipv6) |ip6| {
        var src_buf: [39]u8 = undefined;
        var dst_buf: [39]u8 = undefined;
        const src_ip = ip6.srcIpStr(&src_buf);
        const dst_ip = ip6.dstIpStr(&dst_buf);

        if (pkt.tcp) |t| {
            var flags_buf: [8]u8 = undefined;
            try writer.print("{s}:{d} -> {s}:{d} TCP [{s}] len={d}\n", .{
                src_ip, t.src_port, dst_ip, t.dst_port, t.flags.format(&flags_buf), t.payload.len,
            });
        } else if (pkt.udp) |u| {
            try writer.print("{s}:{d} -> {s}:{d} UDP len={d}\n", .{
                src_ip, u.src_port, dst_ip, u.dst_port, u.payload.len,
            });
        } else if (pkt.icmp) |ic| {
            try formatIcmpLine(writer, src_ip, dst_ip, ic);
        } else {
            try writer.print("{s} -> {s} IPv6 next={s}\n", .{
                src_ip, dst_ip, @tagName(ip6.next_header),
            });
        }
    } else if (pkt.ethernet) |eth| {
        switch (eth.ether_type) {
            .arp => try writer.print("ARP\n", .{}),
            else => try writer.print("ETH type=0x{x:0>4}\n", .{eth.ether_type_raw}),
        }
    } else {
        try writer.print("???\n", .{});
    }

    if (flags.hexdump) {
        try hexdump.dump(writer, raw);
        try writer.print("\n", .{});
    }
}
