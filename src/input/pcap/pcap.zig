const std = @import("std");
const helper = @import("helper");

pub const LinkType = enum(u32) {
    ethernet = 1,
    raw = 101,
    loopback = 0,
    linux_sll = 113,
    unknown,

    pub fn fromU32(v: u32) LinkType {
        return std.meta.intToEnum(LinkType, v) catch .unknown;
    }
};

pub const TimestampResolution = enum { microseconds, nanoseconds };

pub const PcapMetadata = struct {
    linktype: LinkType,
    snaplen: u32,
    ts_resolution: TimestampResolution,
    endianness: std.builtin.Endian,
};

pub const Packet = struct {
    ts_sec: u32,
    ts_frac: u32,
    cap: u32,
    len: u32,
    data: []const u8,
};

pub const PcapError = error{
    UnsupportedFormat,
    UnsupportedLinkType,
    TruncatedFile,
    InvalidRecord,
};

fn parseGlobalHeader(buf: *const [24]u8) !PcapMetadata {
    const b = buf.*;
    const magic = b[0..4];

    var meta: PcapMetadata = undefined;

    if (std.mem.eql(u8, magic, &[_]u8{ 0xd4, 0xc3, 0xb2, 0xa1 })) {
        meta.endianness = .little;
        meta.ts_resolution = .microseconds;
    } else if (std.mem.eql(u8, magic, &[_]u8{ 0xa1, 0xb2, 0xc3, 0xd4 })) {
        meta.endianness = .big;
        meta.ts_resolution = .microseconds;
    } else if (std.mem.eql(u8, magic, &[_]u8{ 0x4d, 0x3c, 0xb2, 0xa1 })) {
        meta.endianness = .little;
        meta.ts_resolution = .nanoseconds;
    } else if (std.mem.eql(u8, magic, &[_]u8{ 0xa1, 0xb2, 0x3c, 0x4d })) {
        meta.endianness = .big;
        meta.ts_resolution = .nanoseconds;
    } else {
        return PcapError.UnsupportedFormat;
    }

    _ = helper.readInt(u16, meta.endianness, b[4..6]);
    _ = helper.readInt(u16, meta.endianness, b[6..8]);

    meta.snaplen = helper.readInt(u32, meta.endianness, b[16..20]);
    const network = helper.readInt(u32, meta.endianness, b[20..24]);
    meta.linktype = LinkType.fromU32(network);

    return meta;
}

pub const Reader = struct {
    file: std.fs.File,
    io_buf: [8192]u8,
    r: std.fs.File.Reader,

    buffer: []u8,
    done: bool,
    meta: PcapMetadata,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, fileName: []const u8) !Reader {
        var file = try std.fs.cwd().openFile(fileName, .{});
        errdefer file.close();

        var self: Reader = .{
            .file = file,
            .io_buf = undefined,
            .r = undefined,
            .buffer = &[_]u8{},
            .done = false,
            .meta = undefined,
            .allocator = allocator,
        };

        self.r = self.file.reader(&self.io_buf);

        var hdr_bytes: [24]u8 = undefined;
        try helper.readExact(&self.r, hdr_bytes[0..]);

        self.meta = try parseGlobalHeader(&hdr_bytes);

        return self;
    }

    pub fn deinit(self: *Reader) void {
        self.file.close();
        self.done = true;
        if (self.buffer.len != 0) self.allocator.free(self.buffer);
    }

    pub fn next(self: *Reader) !?Packet {
        if (self.done) return null;

        var hdr: [16]u8 = undefined;

        const first = self.r.interface.take(1) catch |err| switch (err) {
            error.EndOfStream => {
                self.done = true;
                return null;
            },
            else => return err,
        };

        hdr[0] = first[0];
        try helper.readExact(&self.r, hdr[1..]);

        const ts_sec = helper.readInt(u32, self.meta.endianness, hdr[0..4]);
        const ts_frac = helper.readInt(u32, self.meta.endianness, hdr[4..8]);
        const cap_len = helper.readInt(u32, self.meta.endianness, hdr[8..12]);
        const len = helper.readInt(u32, self.meta.endianness, hdr[12..16]);

        if (cap_len > self.meta.snaplen) return PcapError.InvalidRecord;
        if (cap_len > len) return PcapError.InvalidRecord;

        const need: usize = @intCast(cap_len);
        if (self.buffer.len < need) {
            const new_cap = @max(need, if (self.buffer.len == 0) need else self.buffer.len * 2);
            if (self.buffer.len == 0) {
                self.buffer = try self.allocator.alloc(u8, new_cap);
            } else {
                self.buffer = try self.allocator.realloc(self.buffer, new_cap);
            }
        }

        try helper.readExact(&self.r, self.buffer[0..need]);

        return Packet{
            .ts_sec = ts_sec,
            .ts_frac = ts_frac,
            .cap = cap_len,
            .len = len,
            .data = self.buffer[0..need],
        };
    }
};
