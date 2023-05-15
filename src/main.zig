// zig version 0.11.0
const std = @import("std");
const os = std.os;
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const heap = std.heap;
const math = std.math;
const stdc = std.c;
const crypto = std.crypto;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const HmacSha1 = crypto.auth.hmac.HmacSha1;
const pwhash = crypto.pwhash;

pub const log_level: std.log.Level = .info;
const info = std.log.info;
const warn = std.log.warn;
const ext_encrypt = ".enc";
const ext_decrypt = ".dec";

pub fn main() !void {
    const stdin = io.getStdIn();
    const stdout = io.getStdOut().writer();
    var arena = heap.ArenaAllocator.init(heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    info("Welcome to aes-my-file.", .{});

    var password_buf: [130]u8 = undefined;
    var password_len: usize = 0;
    var has_password = false;
    // 确保程序退出时安全清零密码内存
    defer @memset(&password_buf, 0);
    var line_buf: [130]u8 = undefined;
    while (true) {
        defer _ = arena.reset(.retain_capacity);
        defer @memset(&line_buf, 0);

        info("{s}", .{"Please select a file..."});
        // 硬编码路径 不使用文件选择对话框 使用时需要把while循环去掉
        // const open_path: ?[]const u8 = "/Users/zhangzhankui/zzk13180/github/aes-my-file/tmp/test.zip.enc";
        const open_path = try openFileDialog(null, null);

        if (open_path) |path| {
            info("{s}", .{path});
            defer stdc.free(@constCast(path.ptr));

            const is_decrypt = mem.endsWith(u8, path, ext_encrypt);

            while (!has_password) {
                @memset(&line_buf, 0);
                try stdout.print("\nPlease enter your password: ", .{});
                const amt = try stdin.read(&line_buf);
                if (amt < 5) {
                    warn("{s}", .{"Password is too short"});
                    continue;
                }
                if (amt > 130) {
                    warn("{s}", .{"Password is too long"});
                    continue;
                }
                const pwd = mem.trimRight(u8, line_buf[0..amt], "\r\n");
                password_len = pwd.len;
                @memcpy(password_buf[0..password_len], pwd);

                if (!is_decrypt) {
                    try stdout.print("Please confirm your password: ", .{});
                    var confirm_buf: [130]u8 = undefined;
                    defer @memset(&confirm_buf, 0);
                    const confirm_amt = try stdin.read(&confirm_buf);
                    const confirm_password = mem.trimRight(u8, confirm_buf[0..confirm_amt], "\r\n");

                    if (!mem.eql(u8, password_buf[0..password_len], confirm_password)) {
                        warn("{s}", .{"Passwords do not match"});
                        @memset(&password_buf, 0);
                        password_len = 0;
                        continue;
                    }
                }
                has_password = true;
            }

            if (is_decrypt) {
                info("{s}", .{"Decrypting file"});
                if (decryptFile(allocator, path, password_buf[0..password_len])) |_| {
                    info("{s}", .{"Success"});
                } else |err| switch (err) {
                    error.FileNotFound => warn("{s}", .{"File Not Found"}),
                    error.BadPathName => warn("{s}", .{"Invalid file path"}),
                    error.AccessDenied => warn("{s}", .{"Access Denied"}),
                    error.PathAlreadyExists => warn("{s}", .{"Output file creation failed: File already exists"}),
                    error.NOpassword => {
                        warn("{s}", .{"No password provided"});
                        @memset(&password_buf, 0);
                        password_len = 0;
                        has_password = false;
                    },
                    else => {
                        warn("{!}", .{err});
                        try waitExit();
                        return;
                    },
                }
            } else {
                info("{s}", .{"Encrypting file"});
                if (encryptFile(allocator, path, password_buf[0..password_len])) |_| {
                    info("{s}", .{"Success"});
                } else |err| switch (err) {
                    error.FileNotFound => warn("{s}", .{"File Not Found"}),
                    error.BadPathName => warn("{s}", .{"Invalid file path"}),
                    error.AccessDenied => warn("{s}", .{"Access Denied"}),
                    error.PathAlreadyExists => warn("{s}", .{"Output file creation failed: File already exists"}),
                    error.NOpassword => {
                        warn("{s}", .{"No password provided"});
                        @memset(&password_buf, 0);
                        password_len = 0;
                        has_password = false;
                    },
                    else => {
                        warn("{!}", .{err});
                        try waitExit();
                        return;
                    },
                }
            }
        } else {
            info("{s}", .{"Exiting. Thanks for using aes-my-file."});
            try waitExit();
            return;
        }
    }
}

fn passwordToKey(password: []const u8) ![32]u8 {
    var dk: [Aes256Gcm.key_length]u8 = undefined;
    if (password.len == 0) return error.NOpassword;
    // TODO: 使用更强的哈希函数，更高的迭代次数，以及随机盐值
    try pwhash.pbkdf2(&dk, password, "AESMYFILE", 5000, HmacSha1);
    return dk;
}

fn encryptFile(allocator: std.mem.Allocator, path: []const u8, password: []const u8) !bool {
    const file = fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| {
        warn("Unable to open file: {s}\n", .{@errorName(err)});
        return err;
    };
    defer file.close();

    const file_info = try file.stat();
    if (file_info.kind != .file) {
        return error.BadPathName;
    }

    const path_len = path.len;
    const out_path: []u8 = try allocator.alloc(u8, path_len + ext_encrypt.len);
    defer allocator.free(out_path);
    @memcpy(out_path[0..path_len], path[0..path_len]);
    @memcpy(out_path[path_len..], ext_encrypt);

    info("Output file: {s}", .{out_path});
    const out_file = try fs.createFileAbsolute(out_path, .{
        .truncate = true,
        .exclusive = true,
        .lock = .exclusive,
    });
    defer out_file.close();

    const max_size = 4096 * 100 - Aes256Gcm.tag_length - Aes256Gcm.nonce_length;
    const file_size = try file.getEndPos();

    const ad = "";
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    var key: [32]u8 = try passwordToKey(password);
    defer @memset(&key, 0);
    var nonce: [Aes256Gcm.nonce_length]u8 = undefined;

    var file_buf = std.ArrayList(u8).init(allocator);
    defer file_buf.deinit();
    var cipher_buf = std.ArrayList(u8).init(allocator);
    defer cipher_buf.deinit();

    var written: usize = 0;
    var read_len: usize = 0;
    info("Encrypting, please wait...", .{});
    while (read_len < file_size) {
        crypto.random.bytes(&nonce);
        const size = @min(max_size, file_size - read_len);
        try file_buf.ensureTotalCapacity(size);
        file_buf.expandToCapacity();
        try cipher_buf.ensureTotalCapacity(size);
        cipher_buf.expandToCapacity();

        read_len += try file.readAll(file_buf.items[0..size]);
        Aes256Gcm.encrypt(cipher_buf.items[0..size], &tag, file_buf.items[0..size], ad, nonce, key);

        written += try out_file.write(tag[0..]);
        written += try out_file.write(nonce[0..]);
        written += try out_file.write(cipher_buf.items[0..size]);
    }
    try out_file.setEndPos(written);
    return true;
}

fn decryptFile(allocator: std.mem.Allocator, path: []const u8, password: []const u8) !bool {
    const file = fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| {
        warn("Unable to open file: {s}\n", .{@errorName(err)});
        return err;
    };
    defer file.close();

    const file_info = try file.stat();
    if (file_info.kind != .file) {
        return error.BadPathName;
    }

    const path_original_len = path.len - ext_encrypt.len;
    const path_original: []const u8 = path[0..path_original_len];
    const last_dot = mem.lastIndexOfScalar(u8, path_original, '.') orelse path_original.len;

    const ext_original = path_original[last_dot..];
    const folder_original = path_original[0..last_dot];

    const out_path: []u8 = try mem.concat(allocator, u8, &[_][]const u8{
        folder_original,
        ext_decrypt,
        ext_original,
    });
    defer allocator.free(out_path);

    info("Output file: {s}", .{out_path});
    const out_file = try fs.createFileAbsolute(out_path, .{
        .truncate = true,
        .exclusive = true,
        .lock = .exclusive,
    });
    defer out_file.close();

    const max_size = 4096 * 100;
    const file_size = try file.getEndPos();

    const ad = "";
    var key: [32]u8 = try passwordToKey(password);
    defer @memset(&key, 0);

    var file_buf = std.ArrayList(u8).init(allocator);
    defer file_buf.deinit();
    var decrypted_buf = std.ArrayList(u8).init(allocator);
    defer decrypted_buf.deinit();

    var written: usize = 0;
    var read_len: usize = 0;
    info("Decrypting, please wait...", .{});
    while (read_len < file_size) {
        const size = @min(max_size, file_size - read_len);
        try file_buf.ensureTotalCapacity(size);
        file_buf.expandToCapacity();
        try decrypted_buf.ensureTotalCapacity(size);
        decrypted_buf.expandToCapacity();

        read_len += try file.readAll(file_buf.items[0..size]);

        const label_len = Aes256Gcm.tag_length + Aes256Gcm.nonce_length;

        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        @memcpy(tag[0..], file_buf.items[0..Aes256Gcm.tag_length]);

        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        @memcpy(nonce[0..], file_buf.items[Aes256Gcm.tag_length..label_len]);

        try Aes256Gcm.decrypt(decrypted_buf.items[label_len..size], file_buf.items[label_len..size], tag, ad, nonce, key);

        written += try out_file.write(decrypted_buf.items[label_len..size]);
    }
    return true;
}

fn waitExit() !void {
    const stdin = io.getStdIn();
    const stdout = io.getStdOut().writer();
    try stdout.print("\nPress Enter to exit.", .{});
    var line_buf: [20]u8 = undefined;
    const amt = try stdin.read(&line_buf);
    _ = amt;
}

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    const prefix = "\n[" ++ comptime level.asText() ++ "] ";
    const stderr = io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\n", args) catch return;
}

// #region OpenDialog
// https://github.com/fabioarnold/nfd-zig
const char_t = u8;
const result_t = c_int;
const NFD_ERROR: c_int = 0;
const NFD_OKAY: c_int = 1;
const NFD_CANCEL: c_int = 2;
const Error = error{
    NfdError,
};
extern fn NFD_OpenDialog(filterList: [*c]const char_t, defaultPath: [*c]const char_t, outPath: [*c][*c]char_t) result_t;
extern fn NFD_GetError() [*c]const u8;
fn openFileError() Error {
    if (NFD_GetError()) |ptr| {
        info("{s}", .{mem.span(ptr)});
    }
    return error.NfdError;
}
fn openFileDialog(filter: ?[:0]const u8, default_path: ?[:0]const u8) Error!?[:0]const u8 {
    var out_path: [*c]u8 = null;
    const result = NFD_OpenDialog(if (filter != null) filter.?.ptr else null, if (default_path != null) default_path.?.ptr else null, &out_path);
    return switch (result) {
        NFD_OKAY => if (out_path == null) null else mem.sliceTo(out_path, 0),
        NFD_ERROR => openFileError(),
        else => null,
    };
}
// #endregion OpenDialog
