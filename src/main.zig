const std = @import("std");
const zls = @import("zls");

const Ast = std.zig.Ast;

pub const std_options = struct {
    pub const log_level = .debug;

    pub fn logFn(
        comptime level: std.log.Level,
        comptime scope: @TypeOf(.EnumLiteral),
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (comptime std.mem.startsWith(u8, @tagName(scope), "zls_")) return;
        std.log.defaultLog(level, scope, format, args);
    }
};

// TODO: Make graphs actually usable
// TODO: Subgraphs of structs/enums/unions/opaques

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2)
        return error.MissingZlsPath;

    var zls_uri = try zls.URI.fromPath(allocator, args[1]);
    defer allocator.free(zls_uri);

    var config = zls.Config{};
    var version: ?zls.ZigVersionWrapper = null;

    try zls.configuration.configChanged(&config, &version, allocator, null);

    var server = try zls.Server.create(allocator, &config, null, false, false);
    server.offset_encoding = .@"utf-8";
    defer server.destroy();

    var w = std.io.getStdOut().writer();
    try w.writeAll(
        \\strict digraph zls {
        \\concentrate=true;
        \\layout="fdp";
        \\overlap = false;
        \\splines = true;
        \\node [shape="box"]
        \\
    );

    var iterable_dir = try std.fs.openIterableDirAbsolute(args[1], .{});
    defer iterable_dir.close();

    var walker = try iterable_dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;
        if (std.mem.indexOf(u8, entry.path, "zig-cache") != null or std.mem.indexOf(u8, entry.path, "zig-out") != null) continue;

        const main_path = try std.fs.path.join(allocator, &.{ args[1], entry.path });
        const main_uri = try zls.URI.fromPath(allocator, main_path);
        allocator.free(main_path);

        std.log.info("Graphing {s}", .{main_uri});

        // NOTE: This function takes ownership of the input `text`
        var main_handle = (server.document_store.getOrLoadHandle(main_uri)) orelse @panic("Main file does not exist");

        var nodes = std.ArrayListUnmanaged(CallgraphEntry.Node){};
        var in_cluster = std.ArrayListUnmanaged(CallgraphEntry){};
        var cross_cluster = std.ArrayListUnmanaged(CallgraphEntry){};

        var ctx = CallgraphContext{
            .zls_uri_ = zls_uri,
            .server = server,
            .handle = main_handle,
            .writer = w,

            .nodes = &nodes,
            .in_cluster = &in_cluster,
            .cross_cluster = &cross_cluster,
        };
        try zls.ast.iterateChildrenRecursive(main_handle.tree, 0, &ctx, anyerror, CallgraphContext.callback);

        try w.print("subgraph \"cluster_{}\" {{\n", .{std.zig.fmtEscapes(main_handle.uri)});

        try w.print("label=\"{}\";\n", .{std.zig.fmtEscapes(entry.path)});

        for (nodes.items) |o| {
            try w.print("\"{}\" [label=\"{}\"];\n", .{ std.zig.fmtEscapes(o.id), std.zig.fmtEscapes(o.label) });
        }
        for (in_cluster.items) |o| {
            try w.print("\"{}\" -> \"{}\";\n", .{ std.zig.fmtEscapes(o.from), std.zig.fmtEscapes(o.to) });
        }
        try w.writeAll("}\n");

        for (cross_cluster.items) |o| {
            try w.print("\"{}\" -> \"{}\";\n", .{ std.zig.fmtEscapes(o.from), std.zig.fmtEscapes(o.to) });
        }
    }

    try w.writeAll("}");
}

const CallgraphEntry = struct {
    const Node = struct {
        id: []const u8,
        label: []const u8,
    };

    from: []const u8,
    to: []const u8,
};

const CallgraphContext = struct {
    zls_uri_: []const u8,
    server: *zls.Server,
    handle: *const zls.DocumentStore.Handle,
    writer: std.fs.File.Writer,

    nodes: *std.ArrayListUnmanaged(CallgraphEntry.Node),

    in_cluster: *std.ArrayListUnmanaged(CallgraphEntry),
    cross_cluster: *std.ArrayListUnmanaged(CallgraphEntry),

    func_stack: std.BoundedArray(struct { node: Ast.Node.Index, loc: zls.offsets.Loc }, 16) = .{},

    fn callback(ctx: *@This(), tree: Ast, node: Ast.Node.Index) anyerror!void {
        _ = .{ ctx, tree, node };

        const arena = ctx.server.arena.allocator();
        const handle = ctx.handle;

        var current_func = if (ctx.func_stack.len != 0) ctx.func_stack.buffer[ctx.func_stack.len - 1] else null;
        if (current_func) |cf| {
            if (zls.offsets.nodeToLoc(tree, node).start >= cf.loc.end) {
                // std.log.info("Leaving function {s}", .{zls.analysis.getDeclName(tree, cf.node).?});
                _ = ctx.func_stack.pop();
            }
        }

        const tags = tree.nodes.items(.tag);
        switch (tags[node]) {
            .fn_decl => {
                // std.log.info("Entering function {s}", .{zls.analysis.getDeclName(tree, node).?});
                try ctx.func_stack.append(.{
                    .node = node,
                    .loc = zls.offsets.nodeToLoc(tree, node),
                });

                current_func = ctx.func_stack.buffer[ctx.func_stack.len - 1];

                const from_id = try std.fmt.allocPrint(arena, "{s}#{s}", .{
                    handle.uri,
                    zls.analysis.getDeclName(tree, current_func.?.node).?,
                });
                const from_label = zls.analysis.getDeclName(tree, current_func.?.node).?;

                try ctx.nodes.append(ctx.server.allocator, .{
                    .id = from_id,
                    .label = from_label,
                });
            },
            .call,
            .call_comma,
            .async_call,
            .async_call_comma,
            .call_one,
            .call_one_comma,
            .async_call_one,
            .async_call_one_comma,
            => {
                var nodes: [1]Ast.Node.Index = undefined;
                const full = tree.fullCall(&nodes, node) orelse unreachable;

                const source_index = tree.tokens.items(.start)[tree.lastToken(full.ast.fn_expr)];
                const pos_context = try zls.analysis.getPositionContext(ctx.server.arena.allocator(), handle.text, source_index, true);

                switch (pos_context) {
                    .field_access => |loc| {
                        const accesses = try ctx.server.getSymbolFieldAccesses(handle, source_index, loc) orelse return;

                        for (accesses) |decl_handle| {
                            var new_handle: *const zls.DocumentStore.Handle = decl_handle.handle;
                            const name_token = switch (decl_handle.decl.*) {
                                .ast_node => |accessed_node| block: {
                                    if (try zls.analysis.resolveVarDeclAlias(ctx.server.arena.allocator(), &ctx.server.document_store, .{ .node = accessed_node, .handle = new_handle })) |result| {
                                        new_handle = result.handle;

                                        break :block result.nameToken();
                                    }

                                    break :block zls.analysis.getDeclNameToken(new_handle.tree, accessed_node) orelse continue;
                                },
                                else => decl_handle.nameToken(),
                            };

                            if (current_func != null and std.mem.startsWith(u8, new_handle.uri, ctx.zls_uri_)) {
                                const from_id = try std.fmt.allocPrint(arena, "{s}#{s}", .{
                                    handle.uri,
                                    zls.analysis.getDeclName(tree, current_func.?.node).?,
                                });
                                const to_id = try std.fmt.allocPrint(arena, "{s}#{s}", .{
                                    new_handle.uri,
                                    new_handle.tree.tokenSlice(name_token),
                                });

                                try (if (std.mem.eql(u8, handle.uri, new_handle.uri)) ctx.in_cluster else ctx.cross_cluster).append(ctx.server.allocator, .{
                                    .from = from_id,
                                    .to = to_id,
                                });
                            }
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }
};
