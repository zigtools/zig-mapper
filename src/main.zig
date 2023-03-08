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
        defer {
            server.maybeFreeArena();
        }

        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;
        if (std.mem.indexOf(u8, entry.path, "zig-cache") != null or std.mem.indexOf(u8, entry.path, "zig-out") != null) continue;

        const main_path = try std.fs.path.join(allocator, &.{ args[1], entry.path });
        const main_uri = try zls.URI.fromPath(allocator, main_path);
        allocator.free(main_path);

        std.log.info("Graphing {s}", .{main_uri});

        // NOTE: This function takes ownership of the input `text`
        var handle = (server.document_store.getOrLoadHandle(main_uri)) orelse @panic("Main file does not exist");

        try emit(server, zls_uri, handle, w);
    }

    try w.writeAll("}");
}

fn emit(
    server: *zls.Server,
    zls_uri: []const u8,
    handle: *const zls.DocumentStore.Handle,
    writer: anytype,
) !void {
    var ctx = CallgraphContext{
        .zls_uri = zls_uri,
        .server = server,
        .handle = handle,
        .writer = writer,
    };
    try ctx.init();
    try zls.ast.iterateChildrenRecursive(handle.tree, 0, &ctx, anyerror, CallgraphContext.callback);

    try writeCluster(ctx, 0, writer);
    for (ctx.connections.items) |o| {
        try writer.print("\"{}\" -> \"{}\";\n", .{ std.zig.fmtEscapes(o.from), std.zig.fmtEscapes(o.to) });
    }
}

fn writeCluster(ctx: CallgraphContext, cluster_idx: usize, writer: anytype) !void {
    const cluster = ctx.clusters.items[cluster_idx];

    try writer.print("subgraph \"cluster_{x}\" {{\n", .{cluster.hash});

    for (cluster.subclusters.items) |s| {
        try writeCluster(ctx, s, writer);
    }

    for (cluster.nodes.items) |o| {
        try writer.print("\"{}\" [label=\"{}\"];\n", .{ std.zig.fmtEscapes(o.id), std.zig.fmtEscapes(o.label) });
    }

    try writer.writeAll("}\n");
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
    const Scope = struct {
        const Kind = enum {
            func,
            container,
        };

        node: Ast.Node.Index,
        loc: zls.offsets.Loc,

        kind: Kind,
        cluster: usize = 0,
    };

    const Cluster = struct {
        hash: u64,
        label: []const u8,

        nodes: std.ArrayListUnmanaged(CallgraphEntry.Node) = .{},
        subclusters: std.ArrayListUnmanaged(usize) = .{},
    };

    zls_uri: []const u8,
    server: *zls.Server,
    handle: *const zls.DocumentStore.Handle,
    writer: std.fs.File.Writer,

    clusters: std.ArrayListUnmanaged(Cluster) = .{},
    connections: std.ArrayListUnmanaged(CallgraphEntry) = .{},
    scope_stack: std.BoundedArray(Scope, 128) = .{},

    fn init(ctx: *@This()) !void {
        try ctx.clusters.append(ctx.server.arena.allocator(), .{ .hash = std.hash_map.hashString(ctx.handle.uri) });
        try ctx.scope_stack.append(.{
            .node = 0,
            .loc = .{
                .start = 0,
                .end = ctx.handle.text.len,
            },

            .kind = .container,
            .cluster = 0,
        });
    }

    fn currentScope(ctx: *@This()) ?Scope {
        return if (ctx.scope_stack.len != 0)
            ctx.scope_stack.buffer[ctx.scope_stack.len - 1]
        else
            null;
    }

    fn currentContainer(ctx: *@This()) ?Scope {
        var it = std.mem.reverseIterator(ctx.scope_stack.constSlice());
        while (it.next()) |scope| {
            if (scope.kind == .container) return scope;
        }
        return null;
    }

    fn currentFunction(ctx: *@This()) ?Scope {
        var it = std.mem.reverseIterator(ctx.scope_stack.constSlice());
        while (it.next()) |scope| {
            if (scope.kind == .func) return scope;
        }
        return null;
    }

    fn maybeInvalidateScope(ctx: *@This(), current_node: Ast.Node.Index) void {
        var curr = ctx.currentScope();
        if (curr) |cf| {
            if (zls.offsets.nodeToLoc(ctx.handle.tree, current_node).start >= cf.loc.end) {
                // std.log.info("Leaving function {s}", .{zls.analysis.getDeclName(ctx.handle.tree, cf.node).?});
                _ = ctx.scope_stack.pop();
            }
        }
    }

    fn currentFunctionId(ctx: *@This()) ![]const u8 {
        return std.fmt.allocPrint(ctx.server.arena.allocator(), "{s}#{d}", .{ ctx.handle.uri, ctx.currentFunction().?.node });
    }

    fn currentFunctionName(ctx: *@This()) []const u8 {
        return zls.analysis.getDeclName(ctx.handle.tree, ctx.currentFunction().?.node).?;
    }

    fn callback(ctx: *@This(), tree: Ast, node: Ast.Node.Index) anyerror!void {
        _ = .{ ctx, tree, node };

        const arena = ctx.server.arena.allocator();
        const handle = ctx.handle;

        ctx.maybeInvalidateScope(node);

        const tags = tree.nodes.items(.tag);
        switch (tags[node]) {
            .local_var_decl,
            .global_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const full = tree.fullVarDecl(node).?;

                if (full.ast.init_node == 0) return;
                const subnode = full.ast.init_node;

                switch (tags[subnode]) {
                    .container_decl,
                    .container_decl_trailing,
                    .container_decl_arg,
                    .container_decl_arg_trailing,
                    .container_decl_two,
                    .container_decl_two_trailing,
                    .tagged_union,
                    .tagged_union_trailing,
                    .tagged_union_two,
                    .tagged_union_two_trailing,
                    .tagged_union_enum_tag,
                    .tagged_union_enum_tag_trailing,
                    => {
                        var hasher = std.hash.Wyhash.init(0);

                        hasher.update(ctx.handle.uri);
                        hasher.update(&std.mem.toBytes(node));

                        try ctx.clusters.append(arena, .{
                            .hash = hasher.final(),
                        });

                        try ctx.clusters.items[ctx.currentContainer().?.cluster].subclusters.append(arena, ctx.clusters.items.len - 1);

                        try ctx.scope_stack.append(.{
                            .node = subnode,
                            .loc = zls.offsets.nodeToLoc(tree, subnode),
                            .kind = .container,
                            .cluster = ctx.clusters.items.len - 1,
                        });
                    },
                    else => {},
                }
            },
            .fn_decl => {
                try ctx.scope_stack.append(.{
                    .node = node,
                    .loc = zls.offsets.nodeToLoc(tree, node),
                    .kind = .func,
                });

                try ctx.clusters.items[ctx.currentContainer().?.cluster].nodes.append(arena, .{
                    .id = try ctx.currentFunctionId(),
                    .label = ctx.currentFunctionName(),
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
                            const decl_node = switch (decl_handle.decl.*) {
                                .ast_node => |accessed_node| block: {
                                    if (try zls.analysis.resolveVarDeclAlias(ctx.server.arena.allocator(), &ctx.server.document_store, .{ .node = accessed_node, .handle = new_handle })) |result| {
                                        new_handle = result.handle;

                                        break :block result.decl.ast_node;
                                    }

                                    break :block accessed_node;
                                },
                                else => continue,
                            };

                            if (ctx.currentScope() == null or ctx.currentScope().?.kind == .container or !std.mem.startsWith(u8, new_handle.uri, ctx.zls_uri))
                                break;

                            const to_id = try std.fmt.allocPrint(arena, "{s}#{d}", .{
                                new_handle.uri,
                                decl_node,
                            });

                            try ctx.connections.append(arena, .{
                                .from = try ctx.currentFunctionId(),
                                .to = to_id,
                            });
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }
};
