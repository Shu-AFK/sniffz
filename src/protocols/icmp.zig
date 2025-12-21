// Public ICMP entry point: wraps ICMPv4 + ICMPv6 into a tagged union.

pub const icmp4 = @import("icmp4.zig");
pub const icmp6 = @import("icmp6.zig");

pub const Version = enum {
    v4,
    v6,
};

pub const Icmp = union(enum) {
    v4: icmp4.Packet,
    v6: icmp6.Packet,

    pub fn parse(version: Version, data: []const u8) !Icmp {
        return switch (version) {
            .v4 => .{ .v4 = try icmp4.parse(data) },
            .v6 => .{ .v6 = try icmp6.parse(data) },
        };
    }

    pub fn typeName(self: Icmp) []const u8 {
        return switch (self) {
            .v4 => |p| p.typeName(),
            .v6 => |p| p.typeName(),
        };
    }

    pub fn codeName(self: Icmp) []const u8 {
        return switch (self) {
            .v4 => |p| p.codeName(),
            .v6 => |p| p.codeName(),
        };
    }

    pub fn typeCode(self: Icmp) struct { type: u8, code: u8 } {
        return switch (self) {
            .v4 => |p| .{ .type = @intFromEnum(p.type), .code = p.code },
            .v6 => |p| .{ .type = @intFromEnum(p.type), .code = p.code },
        };
    }
};
