const std = @import("std");

pub const ReadError = error{
    TruncatedFile,
};

pub fn readInt(comptime T: type, endian: std.builtin.Endian, bytes: []const u8) T {
    comptime {
        if (@typeInfo(T) != .int) @compileError("T must be an integer type");
    }
    std.debug.assert(bytes.len >= @sizeOf(T));
    return std.mem.readInt(T, bytes[0..@sizeOf(T)], endian);
}

pub fn readExact(r: anytype, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const chunk = r.*.interface.take(buf.len - off) catch |err| switch (err) {
            error.EndOfStream => return ReadError.TruncatedFile,
            else => return err,
        };
        std.mem.copyForwards(u8, buf[off .. off + chunk.len], chunk);
        off += chunk.len;
    }
}
