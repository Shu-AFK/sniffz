const std = @import("std");

pub const Type = enum(u8) {
    destination_unreachable = 1,
    packet_too_big = 2,
    time_exceeded = 3,
    parameter_problem = 4,

    echo_request = 128,
    echo_reply = 129,

    router_solicitation = 133,
    router_advertisement = 134,
    neighbor_solicitation = 135,
    neighbor_advertisement = 136,

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
            .echo_request => "Echo Request",
            .echo_reply => "Echo Reply",
            .destination_unreachable => "Destination Unreachable",
            .packet_too_big => "Packet Too Big",
            .time_exceeded => "Time Exceeded",
            .parameter_problem => "Parameter Problem",
            .router_solicitation => "Router Solicitation",
            .router_advertisement => "Router Advertisement",
            .neighbor_solicitation => "Neighbor Solicitation",
            .neighbor_advertisement => "Neighbor Advertisement",
            _ => "Unknown",
        };
    }

    pub fn codeName(self: Packet) []const u8 {
        return switch (self.type) {
            .destination_unreachable => switch (self.code) {
                0 => "No Route",
                1 => "Admin Prohibited",
                3 => "Address Unreachable",
                4 => "Port Unreachable",
                else => "Unknown",
            },
            .time_exceeded => switch (self.code) {
                0 => "Hop Limit Exceeded",
                1 => "Fragment Reassembly Time Exceeded",
                else => "Unknown",
            },
            .parameter_problem => switch (self.code) {
                0 => "Erroneous Header Field",
                1 => "Unrecognized Next Header",
                2 => "Unrecognized Option",
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
