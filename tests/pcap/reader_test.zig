const std = @import("std");
const pcap = @import("pcap");

fn openReader(alloc: std.mem.Allocator, path: []const u8) !pcap.Reader {
    return try pcap.Reader.init(alloc, path);
}

test "pcap empty" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var r = try openReader(alloc, "testdata/pcap/empty.pcap");
    defer r.deinit();

    try std.testing.expect((try r.next()) == null);
}

test "pcap good" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var r = try openReader(alloc, "testdata/pcap/good.pcap");
    defer r.deinit();

    const pkt = (try r.next()) orelse return error.TestExpectedPacket;
    try std.testing.expect(pkt.cap > 0);
    try std.testing.expect(pkt.len >= pkt.cap);
}

test "pcap truncated" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var r = try openReader(alloc, "testdata/pcap/truncated.pcap");
    defer r.deinit();

    try std.testing.expectError(pcap.PcapError.TruncatedFile, r.next());
}

test "pcap shortdata" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var r = try openReader(alloc, "testdata/pcap/shortdata.pcap");
    defer r.deinit();

    var got_trunc = false;
    while (true) {
        const res = r.next();
        if (res) |_| {} else |err| {
            if (err == pcap.PcapError.TruncatedFile) got_trunc = true;
            break;
        }
    }
    try std.testing.expect(got_trunc);
}

test "pcap badlen" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var r = try openReader(alloc, "testdata/pcap/badlen.pcap");
    defer r.deinit();

    try std.testing.expectError(pcap.PcapError.InvalidRecord, r.next());
}

test "pcap badmagic" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    try std.testing.expectError(
        pcap.PcapError.UnsupportedFormat,
        openReader(alloc, "testdata/pcap/badmagic.pcap"),
    );
}

test "pcap emptyfile" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var res = openReader(alloc, "testdata/pcap/emptyfile.pcap");
    if (res) |*r| {
        defer r.deinit();
        return error.TestExpectedInitFailure;
    } else |err| {
        try std.testing.expect(
            err == pcap.PcapError.UnsupportedFormat or
                err == pcap.PcapError.TruncatedFile,
        );
    }
}
