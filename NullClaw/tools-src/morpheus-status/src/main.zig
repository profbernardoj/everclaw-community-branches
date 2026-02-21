// morpheus-status — Native Zig tool for NullClaw
//
// Checks EverClaw proxy health from inside NullClaw's process.
// Build: zig build -Doptimize=ReleaseSmall
// Output: ~50 KB static binary
//
// STATUS: Scaffold only — community TODO to implement HTTP client.
// For now, use the shell alternative: curl -sf http://127.0.0.1:8083/health

const std = @import("std");
const net = std.net;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    // Connect to the proxy health endpoint
    const address = net.Address.parseIp4("127.0.0.1", 8083) catch {
        try stdout.print("❌ Morpheus proxy: invalid address\n", .{});
        return;
    };

    const stream = net.tcpConnectToAddress(address) catch {
        try stdout.print("❌ Morpheus proxy: connection refused (port 8083)\n", .{});
        try stdout.print("   Start it: cd ~/.everclaw && bash scripts/start.sh\n", .{});
        return;
    };
    defer stream.close();

    // Send HTTP GET /health
    const request = "GET /health HTTP/1.1\r\nHost: 127.0.0.1:8083\r\nConnection: close\r\n\r\n";
    stream.writeAll(request) catch {
        try stdout.print("❌ Morpheus proxy: write failed\n", .{});
        return;
    };

    // Read response
    var buf: [4096]u8 = undefined;
    var total: usize = 0;

    while (true) {
        const n = stream.read(buf[total..]) catch break;
        if (n == 0) break;
        total += n;
        if (total >= buf.len) break;
    }

    const response = buf[0..total];

    // Check for 200 OK
    if (std.mem.startsWith(u8, response, "HTTP/1.1 200") or
        std.mem.startsWith(u8, response, "HTTP/1.0 200"))
    {
        // Find body (after \r\n\r\n)
        if (std.mem.indexOf(u8, response, "\r\n\r\n")) |body_start| {
            const body = response[body_start + 4 ..];
            try stdout.print("✅ Morpheus proxy healthy\n{s}\n", .{body});
        } else {
            try stdout.print("✅ Morpheus proxy healthy\n", .{});
        }
    } else {
        try stdout.print("❌ Morpheus proxy unhealthy\n{s}\n", .{response});
    }
}
