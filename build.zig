const std = @import("std");
const FileSource = std.build.FileSource;

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "aes-my-file",
        .root_source_file = FileSource.relative("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cflags = [_][]const u8{"-Wall"};
    exe.addIncludePath(FileSource.relative("src/nfd/include"));
    exe.addCSourceFile(.{ .file = .{ .path = "src/nfd/nfd_common.c" }, .flags = &cflags });
    if (exe.target.isDarwin()) {
        exe.addCSourceFile(.{ .file = .{ .path = "src/nfd/nfd_cocoa.m" }, .flags = &cflags });
    } else if (exe.target.isWindows()) {
        exe.addCSourceFile(.{ .file = .{ .path = "src/nfd/nfd_win.cpp" }, .flags = &cflags });
    } else {
        exe.addCSourceFile(.{ .file = .{ .path = "src/nfd/nfd_gtk.c" }, .flags = &cflags });
    }

    exe.linkLibC();
    if (exe.target.isDarwin()) {
        exe.linkFramework("AppKit");
    } else if (exe.target.isWindows()) {
        exe.linkSystemLibrary("shell32");
        exe.linkSystemLibrary("ole32");
        exe.linkSystemLibrary("uuid"); // needed by MinGW
    } else {
        exe.linkSystemLibrary("atk-1.0");
        exe.linkSystemLibrary("gdk-3");
        exe.linkSystemLibrary("gtk-3");
        exe.linkSystemLibrary("glib-2.0");
        exe.linkSystemLibrary("gobject-2.0");
    }
    exe.installHeadersDirectory("src/nfd/include", ".");
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
