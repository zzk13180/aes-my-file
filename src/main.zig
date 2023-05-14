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
    var password: ?[]const u8 = null;
    while (true) {
        if (password == null) {
            try stdout.print("\nplease enter your password:", .{});
            var line_buf: [130]u8 = undefined;
            const amt = try stdin.read(&line_buf);
            if (amt < 5) {
                warn("{s}", .{"Password is too short"});
                continue;
            }
            if (amt > 130) {
                warn("{s}", .{"Password is too long"});
                continue;
            }
            password = mem.trimRight(u8, line_buf[0..amt], "\r\n");
            try stdout.print("\nyour password:{?s}\n", .{password});
        }
        info("{s}", .{"Please select a file"});
        const open_path = try openFileDialog("*", null);
        if (open_path) |path| {
            defer stdc.free(@intToPtr(*anyopaque, @ptrToInt(path.ptr)));
            if (!!mem.endsWith(u8, path, ext_encrypt)) {
                info("{s}", .{"Decrypting file"});
                if (decryptFile(allocator, path, password)) |_| {
                    info("{s}", .{"Success"});
                } else |err| switch (err) {
                    error.FileNotFound => warn("{s}", .{"File Not Found"}),
                    error.BadPathName => warn("{s}", .{"Bad Path Name"}),
                    error.AccessDenied => warn("{s}", .{"Access Denied"}),
                    error.PathAlreadyExists => warn("{s}", .{"Failed while creating Output file, file already exists"}),
                    error.NOpassword => {
                        warn("{s}", .{"NO password"});
                        password = null;
                    },
                    else => {
                        warn("{!}", .{err});
                        try waitExit();
                        return;
                    },
                }
            } else {
                info("{s}", .{"Encrypting file"});
                if (encryptFile(allocator, path, password)) |_| {
                    info("{s}", .{"Success"});
                } else |err| switch (err) {
                    error.FileNotFound => warn("{s}", .{"File Not Found"}),
                    error.BadPathName => warn("{s}", .{"Bad Path Name"}),
                    error.AccessDenied => warn("{s}", .{"Access Denied"}),
                    error.PathAlreadyExists => warn("{s}", .{"Failed while creating Output file, file already exists"}),
                    error.NOpassword => {
                        warn("{s}", .{"NO password"});
                        password = null;
                    },
                    else => {
                        warn("{!}", .{err});
                        try waitExit();
                        return;
                    },
                }
            }
        } else {
            info("{s}", .{"Exiting. thans for using aes-my-file."});
            try waitExit();
            return;
        }
    }
}

fn passwordToKey(password: ?[]const u8) ![32]u8 {
    var dk: [Aes256Gcm.key_length]u8 = undefined;
    const _password: []const u8 = password orelse "";
    if (_password.len == 0) return error.NOpassword;
    try pwhash.pbkdf2(&dk, _password, "AESMYFILE", 5000, HmacSha1);
    return dk;
}

fn encryptFile(allocator: std.mem.Allocator, path: []const u8, password: ?[]const u8) !bool {
    const file = fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| {
        warn("Unable to open file: {s}\n", .{@errorName(err)});
        return err;
    };
    defer file.close();

    const file_info = try file.stat();
    if (file_info.kind != .File) {
        return error.BadPathName;
    }

    const path_len = path.len;
    const out_path: []u8 = try allocator.alloc(u8, path_len + ext_encrypt.len);
    mem.copy(u8, out_path[0..path_len], path[0..path_len]);
    mem.copy(u8, out_path[path_len..], ext_encrypt);

    info("Output file: {s}", .{out_path});
    const out_file = try fs.createFileAbsolute(out_path, .{
        .truncate = true,
        .exclusive = true,
        .lock = .Exclusive,
    });
    defer out_file.close();

    const max_size = 4096 * 100 - Aes256Gcm.tag_length - Aes256Gcm.nonce_length;
    const file_size = try file.getEndPos();

    const ad = "";
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    const key: [32]u8 = try passwordToKey(password);
    var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
    crypto.random.bytes(&nonce);

    var file_buf = std.ArrayList(u8).init(allocator);
    defer file_buf.deinit();
    var cipher_buf = std.ArrayList(u8).init(allocator);
    defer cipher_buf.deinit();

    var written: usize = 0;
    var read_len: usize = 0;
    info("Encrypting please wait", .{});
    while (read_len < file_size) {
        const size = @min(max_size, file_size - read_len);
        try file_buf.ensureTotalCapacity(size);
        file_buf.expandToCapacity();
        try cipher_buf.ensureTotalCapacity(size);
        cipher_buf.expandToCapacity();

        read_len += try file.read(file_buf.items[0..size]);
        Aes256Gcm.encrypt(cipher_buf.items[0..size], &tag, file_buf.items[0..size], ad, nonce, key);

        written += try out_file.write(tag[0..]);
        written += try out_file.write(nonce[0..]);
        written += try out_file.write(cipher_buf.items[0..size]);
    }
    try out_file.setEndPos(written);
    return true;
}

fn decryptFile(allocator: std.mem.Allocator, path: []const u8, password: ?[]const u8) !bool {
    const file = fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| {
        warn("Unable to open file: {s}\n", .{@errorName(err)});
        return err;
    };
    defer file.close();

    const file_info = try file.stat();
    if (file_info.kind != .File) {
        return error.BadPathName;
    }

    const path_original_len = path.len - ext_encrypt.len;
    const path_original: []const u8 = path[0..path_original_len];
    const last_dor = mem.lastIndexOfScalar(u8, path_original, '.') orelse path_original.len;

    const ext_original = path_original[last_dor..];
    const folder_original = path_original[0..last_dor];

    const out_path: []u8 = try mem.concat(allocator, u8, &[_][]const u8{
        folder_original,
        ext_decrypt,
        ext_original,
    });

    info("Output file: {s}", .{out_path});
    const out_file = try fs.createFileAbsolute(out_path, .{
        .truncate = true,
        .exclusive = true,
        .lock = .Exclusive,
    });
    defer out_file.close();

    const max_size = 4096 * 100;
    const file_size = try file.getEndPos();

    const ad = "";
    const key: [32]u8 = try passwordToKey(password);

    var file_buf = std.ArrayList(u8).init(allocator);
    defer file_buf.deinit();
    var decrypted_buf = std.ArrayList(u8).init(allocator);
    defer decrypted_buf.deinit();

    var written: usize = 0;
    var read_len: usize = 0;
    info("Encrypting please wait", .{});
    while (read_len < file_size) {
        const size = @min(max_size, file_size - read_len);
        try file_buf.ensureTotalCapacity(size);
        file_buf.expandToCapacity();
        try decrypted_buf.ensureTotalCapacity(size);
        decrypted_buf.expandToCapacity();

        read_len += try file.read(file_buf.items[0..size]);

        const label_len = Aes256Gcm.tag_length + Aes256Gcm.nonce_length;

        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        mem.copy(u8, tag[0..], file_buf.items[0..Aes256Gcm.tag_length]);

        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        mem.copy(u8, nonce[0..], file_buf.items[Aes256Gcm.tag_length..label_len]);

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
