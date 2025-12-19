const pcap = @import("pcap");
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print("usage: {s} <file.pcap>\n", .{args[0]});
        return error.InvalidArguments;
    }

    const path = args[1];

    std.debug.print("sniffz - packet sniffer in zig\n", .{});
    std.debug.print("opening pcap: {s}\n", .{path});

    var reader = try pcap.Reader.init(allocator, path);
    defer reader.deinit();

    var count: usize = 0;
    while (try reader.next()) |pkt| {
        count += 1;
        std.debug.print(
            "#{d} ts={d}.{d} cap={d} len={d}\n",
            .{ count, pkt.ts_sec, pkt.ts_frac, pkt.cap, pkt.len },
        );
    }

    std.debug.print("done, read {d} packets\n", .{count});
}
