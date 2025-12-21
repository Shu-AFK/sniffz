const std = @import("std");

pub const Type = enum(u8) {
    echo_reply = 0,
    destination_unreachable = 3,
    redirection = 5,
    echo_request = 8,
    router_advertisement = 9,
    router_solicitation = 10,
    time_exceeded = 11,
    parameter_problem = 12,
    timestamp_request = 13,
    timestamp_reply = 14,
    _,
};

pub const Packet = struct {
    type: Type,
    code: u8,
    checksum: u16,
    rest: [4]u8,
    payload: []const u8,

    pub fn typeName(self: Packet) []const u8 {
        return switch (self.type) {
            .echo_reply => "Echo Reply",
            .echo_request => "Echo Request",
            .destination_unreachable => "Destination Unreachable",
            .redirection => "Redirect",
            .router_advertisement => "Router Advertisement",
            .router_solicitation => "Router Solicitation",
            .time_exceeded => "Time Exceeded",
            .parameter_problem => "Parameter Problem",
            .timestamp_request => "Timestamp Request",
            .timestamp_reply => "Timestamp Reply",
            _ => "Unknown",
        };
    }

    pub fn codeName(self: Packet) []const u8 {
        return switch (self.type) {
            .destination_unreachable => switch (self.code) {
                0 => "Network Unreachable",
                1 => "Host Unreachable",
                2 => "Protocol Unreachable",
                3 => "Port Unreachable",
                4 => "Fragmentation Needed",
                else => "Unknown",
            },
            .redirection => switch (self.code) {
                0 => "Network Redirect",
                1 => "Host Redirect",
                2 => "TOS Network Redirect",
                3 => "TOS Host Redirect",
                else => "Unknown",
            },
            .time_exceeded => switch (self.code) {
                0 => "TTL Expired",
                1 => "Fragment Reassembly Time Exceeded",
                else => "Unknown",
            },
            .parameter_problem => switch (self.code) {
                0 => "Pointer Indicates Error",
                1 => "Missing Required Option",
                2 => "Bad Length",
                else => "Unknown",
            },
            else => "",
        };
    }
};

pub fn parse(data: []const u8) !Packet {
    if (data.len < 8) return error.TooShort;

    return .{
        .type = @enumFromInt(data[0]),
        .code = data[1],
        .checksum = std.mem.readInt(u16, data[2..4], .big),
        .rest = data[4..8].*,
        .payload = data[8..],
    };
}
