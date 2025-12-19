const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const helper_mod = b.addModule("helper", .{
        .root_source_file = b.path("src/helper.zig"),
        .target = target,
        .optimize = optimize,
    });

    const pcap_mod = b.addModule("pcap", .{
        .root_source_file = b.path("src/input/pcap/pcap.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "helper", .module = helper_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "sniffz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "pcap", .module = pcap_mod },
            },
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);
    if (b.args) |args| run_cmd.addArgs(args);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/test_all.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.root_module.addImport("pcap", pcap_mod);

    const test_step = b.step("test", "Run tests");
    const run_tests = b.addRunArtifact(tests);
    test_step.dependOn(&run_tests.step);
}
