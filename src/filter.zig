const packet = @import("protocols/packet.zig");
const ipv4 = @import("protocols/ipv4.zig");
const ipv6 = @import("protocols/ipv6.zig");
const icmp = @import("protocols/icmp.zig");

const std = @import("std");

pub const IpAddr = union(enum) {
    v4: [4]u8,
    v6: [16]u8,
};

pub const Filter = union(enum) {
    tcp,
    udp,

    icmp,
    icmp4,
    icmp6,

    port: u16,
    src: IpAddr,
    dst: IpAddr,
    ip: IpAddr,
};

pub fn parse(allocator: std.mem.Allocator, input: []const u8) ![]Filter {
    var filters: std.ArrayListUnmanaged(Filter) = .empty;
    var it = std.mem.tokenizeScalar(u8, input, ' ');

    while (it.next()) |token| {
        if (std.mem.eql(u8, token, "tcp")) {
            try filters.append(allocator, .tcp);
        } else if (std.mem.eql(u8, token, "udp")) {
            try filters.append(allocator, .udp);
        } else if (std.mem.eql(u8, token, "icmp")) {
            try filters.append(allocator, .icmp);
        } else if (std.mem.eql(u8, token, "icmp4")) {
            try filters.append(allocator, .icmp4);
        } else if (std.mem.eql(u8, token, "icmp6")) {
            try filters.append(allocator, .icmp6);
        } else if (std.mem.eql(u8, token, "port")) {
            const portStr = it.next() orelse return error.MissingPort;
            const port = std.fmt.parseInt(u16, portStr, 10) catch return error.InvalidPort;
            try filters.append(allocator, .{ .port = port });
        } else if (std.mem.eql(u8, token, "ip")) {
            const addr_str = it.next() orelse return error.MissingAddr;
            try filters.append(allocator, .{ .ip = try parseIp(addr_str) });
        } else if (std.mem.eql(u8, token, "src")) {
            const addr_str = it.next() orelse return error.MissingAddr;
            try filters.append(allocator, .{ .src = try parseIp(addr_str) });
        } else if (std.mem.eql(u8, token, "dst")) {
            const addr_str = it.next() orelse return error.MissingAddr;
            try filters.append(allocator, .{ .dst = try parseIp(addr_str) });
        } else {
            return error.WrongFilter;
        }
    }

    return filters.toOwnedSlice(allocator);
}

fn parseIp(s: []const u8) !IpAddr {
    if (std.mem.indexOfScalar(u8, s, ':') != null) {
        return .{ .v6 = try ipv6.parseIpStr(s) };
    } else {
        return .{ .v4 = try ipv4.parseIpStr(s) };
    }
}

pub fn matches(pkt: packet.DecodedPacket, filters: []const Filter) bool {
    for (filters) |f| {
        if (!matchesSingle(pkt, f)) return false;
    }
    return true;
}

fn matchesSingle(pkt: packet.DecodedPacket, filter: Filter) bool {
    return switch (filter) {
        .tcp => pkt.tcp != null,
        .udp => pkt.udp != null,

        .icmp => pkt.icmp != null,

        .icmp4 => blk: {
            if (pkt.icmp) |p| {
                break :blk switch (p) {
                    .v4 => true,
                    .v6 => false,
                };
            }
            break :blk false;
        },

        .icmp6 => blk: {
            if (pkt.icmp) |p| {
                break :blk switch (p) {
                    .v4 => false,
                    .v6 => true,
                };
            }
            break :blk false;
        },

        .port => |p| {
            if (pkt.tcp) |t| return t.src_port == p or t.dst_port == p;
            if (pkt.udp) |u| return u.src_port == p or u.dst_port == p;
            return false;
        },

        .src => |addr| matchAddr(pkt, addr, .src),
        .dst => |addr| matchAddr(pkt, addr, .dst),
        .ip => |addr| matchAddr(pkt, addr, .src) or matchAddr(pkt, addr, .dst),
    };
}

const Direction = enum { src, dst };

fn matchAddr(pkt: packet.DecodedPacket, addr: IpAddr, dir: Direction) bool {
    switch (addr) {
        .v4 => |v4| {
            if (pkt.ipv4) |ip| {
                const pkt_addr = if (dir == .src) ip.src_ip else ip.dst_ip;
                return std.mem.eql(u8, &pkt_addr, &v4);
            }
        },
        .v6 => |v6| {
            if (pkt.ipv6) |ip| {
                // IMPORTANT: adjust these field names if your ipv6 struct uses src_ip/dst_ip instead.
                const pkt_addr = if (dir == .src) ip.src else ip.dst;
                return std.mem.eql(u8, &pkt_addr, &v6);
            }
        },
    }
    return false;
}
