const std = @import("std");
const packet = @import("../protocols/packet.zig");
const ethernet = @import("../protocols/ethernet.zig");

pub fn format(writer: anytype, index: usize, pkt: packet.DecodedPacket) !void {
    try writer.print("#{d:<4} ", .{index});

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
        } else {
            try writer.print("{s} -> {s} {s}\n", .{
                src_ip, dst_ip, @tagName(ip.protocol),
            });
        }
    } else if (pkt.ethernet) |eth| {
        switch (eth.ether_type) {
            .arp => try writer.print("ARP\n", .{}),
            .ipv6 => try writer.print("IPv6 (not implemented)\n", .{}),
            else => try writer.print("ETH type=0x{x:0>4}\n", .{eth.ether_type_raw}),
        }
    } else {
        try writer.print("???\n", .{});
    }
}
