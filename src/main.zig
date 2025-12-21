const std = @import("std");
const clap = @import("clap");
const pcap = @import("pcap");

const filter = @import("filter.zig");
const packet = @import("protocols/packet.zig");
const formatter = @import("output/formatter.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\-v, --verbose          Show verbose output (ethernet info).
        \\-x, --hexdump          Print the hexdump of each packet.
        \\-f, --filter <str>     Filter by port, ip or protocol.
        \\<str>                  PCAP file to read.
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        try diag.reportToFile(.stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try clap.help(stdout, clap.Help, &params, .{});
        try stdout.flush();
        return;
    }

    const path = res.positionals[0] orelse {
        try stdout.print("error: missing required argument: <file>\n", .{});
        try clap.help(stdout, clap.Help, &params, .{});
        try stdout.flush();
        return error.MissingArgument;
    };

    const verbose = res.args.verbose != 0;
    const hexdump = res.args.hexdump != 0;

    const filters = if (res.args.filter) |f|
        try filter.parse(allocator, f)
    else
        &[_]filter.Filter{};
    defer if (res.args.filter != null) allocator.free(filters);

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

        if (filter.matches(dec, filters)) {
            try formatter.format(stdout, count, dec, pkt.data, .{ .verbose = verbose, .hexdump = hexdump });
        }
        try stdout.flush();
    }

    try stdout.print("done, read {d} packets\n", .{count});
    try stdout.flush();
}
