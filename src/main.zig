const pcap = @import("pcap");

const packet = @import("protocols/packet.zig");
const formatter = @import("output/formatter.zig");

const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        try stdout.print("usage: {s} <file.pcap>\n", .{args[0]});
        try stdout.flush();
        return error.InvalidArguments;
    }

    const path = args[1];

    try stdout.print("sniffz - packet sniffer in zig\n", .{});
    try stdout.print("opening pcap: {s}\n", .{path});
    try stdout.flush();

    var reader = try pcap.Reader.init(allocator, path);
    defer reader.deinit();

    var count: usize = 0;
    while (try reader.next()) |pkt| {
        count += 1;

        const dec = packet.DecodedPacket.decode(pkt.data, reader.meta.linktype) catch |err| {
            try stdout.print("#{d:<4} decode error: {}\n", .{ count, err });
            try stdout.flush();
            continue;
        };

        try formatter.format(stdout, count, dec);
        try stdout.flush();
    }

    try stdout.print("done, read {d} packets\n", .{count});
    try stdout.flush();
}
