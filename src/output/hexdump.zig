pub fn dump(writer: anytype, data: []const u8) !void {
    var offset: usize = 0;

    while (offset < data.len) : (offset += 16) {
        const end = @min(offset + 16, data.len);
        const chunk = data[offset..end];

        try writer.print("{x:0>5} ", .{offset});

        var i: usize = 0;
        while (i < 16) : (i += 1) {
            if (i < chunk.len) {
                try writer.print("{x:0>2} ", .{chunk[i]});
            } else {
                try writer.print("   ", .{});
            }
        }

        try writer.print("|", .{});
        for (chunk) |b| {
            const c: u8 = if (b >= 0x20 and b <= 0x7e) b else '.';
            try writer.print("{c}", .{c});
        }
        i = chunk.len;
        while (i < 16) : (i += 1) try writer.print(" ", .{});
        try writer.print("|\n", .{});
    }
}
