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

// TODO: Track functions that don't call any other in-scope functions (example sendInternal)
// TODO: Multiple files
// TODO: Make graphs actually usable

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

    const main_uri = try zls.URI.pathRelative(allocator, zls_uri, "src/Server.zig");
    // NOTE: This function takes ownership of the input `text`
    var main_handle = (server.document_store.getOrLoadHandle(main_uri)) orelse @panic("Main file does not exist");

    const CallgraphEntry = struct {
        const Node = struct {
            id: []const u8,
            label: ?[]const u8 = null,
        };

        from: Node,
        to: Node,
        is_in_same_cluster: bool,
    };

    const CallgraphContext = struct {
        zls_uri_: []const u8,
        server_: *zls.Server,
        handle: *const zls.DocumentStore.Handle,
        writer: std.fs.File.Writer,

        output: *std.ArrayListUnmanaged(CallgraphEntry),
        func_stack: std.BoundedArray(struct { node: Ast.Node.Index, loc: zls.offsets.Loc }, 16) = .{},

        fn callback(ctx: *@This(), tree: Ast, node: Ast.Node.Index) anyerror!void {
            _ = .{ ctx, tree, node };

            const arena = ctx.server_.arena.allocator();
            const handle = ctx.handle;

            const current_func = if (ctx.func_stack.len != 0) ctx.func_stack.buffer[ctx.func_stack.len - 1] else null;
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
                    const pos_context = try zls.analysis.getPositionContext(ctx.server_.arena.allocator(), handle.text, source_index, true);

                    switch (pos_context) {
                        .field_access => |loc| {
                            const accesses = try ctx.server_.getSymbolFieldAccesses(handle, source_index, loc) orelse return;

                            for (accesses) |decl_handle| {
                                var new_handle: *const zls.DocumentStore.Handle = decl_handle.handle;
                                const name_token = switch (decl_handle.decl.*) {
                                    .ast_node => |accessed_node| block: {
                                        if (try zls.analysis.resolveVarDeclAlias(ctx.server_.arena.allocator(), &ctx.server_.document_store, .{ .node = accessed_node, .handle = new_handle })) |result| {
                                            new_handle = result.handle;

                                            break :block result.nameToken();
                                        }

                                        break :block zls.analysis.getDeclNameToken(new_handle.tree, accessed_node) orelse continue;
                                    },
                                    else => decl_handle.nameToken(),
                                };

                                if (current_func != null and std.mem.startsWith(u8, new_handle.uri, ctx.zls_uri_)) {
                                    try ctx.output.append(arena, .{
                                        .from = .{
                                            .id = try std.fmt.allocPrint(arena, "{s}#{s}", .{
                                                handle.uri,
                                                zls.analysis.getDeclName(tree, current_func.?.node).?,
                                            }),
                                            .label = zls.analysis.getDeclName(tree, current_func.?.node).?,
                                        },
                                        .to = .{
                                            .id = try std.fmt.allocPrint(arena, "{s}#{s}", .{
                                                new_handle.uri,
                                                new_handle.tree.tokenSlice(name_token),
                                            }),
                                        },
                                        .is_in_same_cluster = std.mem.eql(u8, handle.uri, new_handle.uri),
                                    });
                                    // try ctx.writer.print("\"{}__{}\" [label=\"{}\"];\n", .{
                                    //     std.zig.fmtEscapes(handle.uri),
                                    //     std.zig.fmtEscapes(zls.analysis.getDeclName(tree, current_func.?.node).?),
                                    //     std.zig.fmtEscapes(zls.analysis.getDeclName(tree, current_func.?.node).?),
                                    // });
                                    // try ctx.writer.print("\"{}__{}\" -> \"{}__{}\";\n", .{
                                    //     std.zig.fmtEscapes(handle.uri),
                                    //     std.zig.fmtEscapes(zls.analysis.getDeclName(tree, current_func.?.node).?),
                                    //     std.zig.fmtEscapes(new_handle.uri),
                                    //     std.zig.fmtEscapes(new_handle.tree.tokenSlice(name_token)),
                                    // });
                                    // std.log.info("{s} {s}", .{ new_handle.uri, new_handle.tree.tokenSlice(name_token) });
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

    var w = std.io.getStdOut().writer();
    try w.writeAll("digraph zls {\n");

    var outp = std.ArrayListUnmanaged(CallgraphEntry){};

    var ctx = CallgraphContext{
        .zls_uri_ = zls_uri,
        .server_ = server,
        .handle = main_handle,
        .writer = w,
        .output = &outp,
    };
    try zls.ast.iterateChildrenRecursive(main_handle.tree, 0, &ctx, anyerror, CallgraphContext.callback);

    try w.print("subgraph cluster_abc {{\n", .{});
    for (outp.items) |o| {
        try w.print("\"{}\" [label=\"{}\"];\n", .{ std.zig.fmtEscapes(o.from.id), std.zig.fmtEscapes(o.from.label.?) });
        if (o.is_in_same_cluster) {
            try w.print("\"{}\" -> \"{}\";\n", .{ std.zig.fmtEscapes(o.from.id), std.zig.fmtEscapes(o.to.id) });
        }
    }
    try w.writeAll("}");

    for (outp.items) |o| {
        if (!o.is_in_same_cluster) {
            try w.print("\"{}\" -> \"{}\";\n", .{ std.zig.fmtEscapes(o.from.id), std.zig.fmtEscapes(o.to.id) });
        }
    }

    try w.writeAll("}");
}
