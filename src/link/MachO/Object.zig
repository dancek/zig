const Object = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const io = std.io;
const log = std.log.scoped(.object);
const macho = std.macho;
const mem = std.mem;

const Allocator = mem.Allocator;
const Symbol = @import("Symbol.zig");
const parseName = @import("Zld.zig").parseName;

usingnamespace @import("commands.zig");

allocator: *Allocator,
arch: ?std.Target.Cpu.Arch = null,
header: ?macho.mach_header_64 = null,
file: ?fs.File = null,
file_offset: ?u32 = null,
name: ?[]u8 = null,

load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},

segment_cmd_index: ?u16 = null,
symtab_cmd_index: ?u16 = null,
dysymtab_cmd_index: ?u16 = null,
build_version_cmd_index: ?u16 = null,
data_in_code_cmd_index: ?u16 = null,
text_section_index: ?u16 = null,

// __DWARF segment sections
dwarf_debug_info_index: ?u16 = null,
dwarf_debug_abbrev_index: ?u16 = null,
dwarf_debug_str_index: ?u16 = null,
dwarf_debug_line_index: ?u16 = null,
dwarf_debug_ranges_index: ?u16 = null,

symtab: std.ArrayListUnmanaged(Symbol) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

data_in_code_entries: std.ArrayListUnmanaged(macho.data_in_code_entry) = .{},

pub fn init(allocator: *Allocator) Object {
    return .{
        .allocator = allocator,
    };
}

pub fn deinit(self: *Object) void {
    for (self.load_commands.items) |*lc| {
        lc.deinit(self.allocator);
    }
    self.load_commands.deinit(self.allocator);
    self.symtab.deinit(self.allocator);
    self.strtab.deinit(self.allocator);
    self.data_in_code_entries.deinit(self.allocator);

    if (self.name) |n| {
        self.allocator.free(n);
    }
}

pub fn closeFile(self: Object) void {
    if (self.file) |f| {
        f.close();
    }
}

pub fn parse(self: *Object) !void {
    var reader = self.file.?.reader();
    if (self.file_offset) |offset| {
        try reader.context.seekTo(offset);
    }

    self.header = try reader.readStruct(macho.mach_header_64);

    if (self.header.?.filetype != macho.MH_OBJECT) {
        log.err("invalid filetype: expected 0x{x}, found 0x{x}", .{ macho.MH_OBJECT, self.header.?.filetype });
        return error.MalformedObject;
    }

    const this_arch: std.Target.Cpu.Arch = switch (self.header.?.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => |value| {
            log.err("unsupported cpu architecture 0x{x}", .{value});
            return error.UnsupportedCpuArchitecture;
        },
    };
    if (this_arch != self.arch.?) {
        log.err("mismatched cpu architecture: expected {s}, found {s}", .{ self.arch.?, this_arch });
        return error.MismatchedCpuArchitecture;
    }

    try self.readLoadCommands(reader);
    if (self.symtab_cmd_index != null) try self.parseSymtab();
    if (self.data_in_code_cmd_index != null) try self.readDataInCode();

    {
        const seg = self.load_commands.items[self.segment_cmd_index.?].Segment;
        for (seg.sections.items) |_, sect_id| {
            try self.parseRelocs(@intCast(u16, sect_id));
        }
    }
}

pub fn readLoadCommands(self: *Object, reader: anytype) !void {
    const offset = self.file_offset orelse 0;
    try self.load_commands.ensureCapacity(self.allocator, self.header.?.ncmds);

    var i: u16 = 0;
    while (i < self.header.?.ncmds) : (i += 1) {
        var cmd = try LoadCommand.read(self.allocator, reader);
        switch (cmd.cmd()) {
            macho.LC_SEGMENT_64 => {
                self.segment_cmd_index = i;
                var seg = cmd.Segment;
                for (seg.sections.items) |*sect, j| {
                    const index = @intCast(u16, j);
                    const segname = parseName(&sect.segname);
                    const sectname = parseName(&sect.sectname);
                    if (mem.eql(u8, segname, "__DWARF")) {
                        if (mem.eql(u8, sectname, "__debug_info")) {
                            self.dwarf_debug_info_index = index;
                        } else if (mem.eql(u8, sectname, "__debug_abbrev")) {
                            self.dwarf_debug_abbrev_index = index;
                        } else if (mem.eql(u8, sectname, "__debug_str")) {
                            self.dwarf_debug_str_index = index;
                        } else if (mem.eql(u8, sectname, "__debug_line")) {
                            self.dwarf_debug_line_index = index;
                        } else if (mem.eql(u8, sectname, "__debug_ranges")) {
                            self.dwarf_debug_ranges_index = index;
                        }
                    } else if (mem.eql(u8, segname, "__TEXT")) {
                        if (mem.eql(u8, sectname, "__text")) {
                            self.text_section_index = index;
                        }
                    }

                    sect.offset += offset;
                    if (sect.reloff > 0) {
                        sect.reloff += offset;
                    }
                }

                seg.inner.fileoff += offset;
            },
            macho.LC_SYMTAB => {
                self.symtab_cmd_index = i;
                cmd.Symtab.symoff += offset;
                cmd.Symtab.stroff += offset;
            },
            macho.LC_DYSYMTAB => {
                self.dysymtab_cmd_index = i;
            },
            macho.LC_BUILD_VERSION => {
                self.build_version_cmd_index = i;
            },
            macho.LC_DATA_IN_CODE => {
                self.data_in_code_cmd_index = i;
                cmd.LinkeditData.dataoff += offset;
            },
            else => {
                log.debug("Unknown load command detected: 0x{x}.", .{cmd.cmd()});
            },
        }
        self.load_commands.appendAssumeCapacity(cmd);
    }
}

const PageReloc = struct {
    const Kind = enum {
        Normal,
        Got,
        Tlv,
    };

    const TargetType = enum {
        Symbol,
        Section,
    };

    kind: Kind,
    target_type: TargetType,
    // TODO preprocess target based on whether it is local to CU, or extern
    target: u32,
    page_op: struct {
        addend: ?u32 = null,
        offset: i32,
    },
    pageoff_op: struct {
        addend: ?u32 = null,
        offset: i32,
    },
};

fn parsePageOff12Reloc(reloc: macho.relocation_info, addend: ?u32) PageReloc {
    assert(reloc.r_length == 2);
    assert(reloc.r_pcrel == 0);

    const kind: PageReloc.Kind = switch (@intToEnum(macho.reloc_type_arm64, reloc.r_type)) {
        .ARM64_RELOC_PAGEOFF12 => .Normal,
        .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => .Got,
        .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => .Tlv,
        else => unreachable,
    };

    const target_type: PageReloc.TargetType = if (reloc.r_extern == 1) .Symbol else .Section;
    const target = if (reloc.r_extern == 1) reloc.r_symbolnum else reloc.r_symbolnum - 1;

    return .{
        .kind = kind,
        .target_type = target_type,
        .target = target,
        .pageoff_op = .{
            .addend = addend,
            .offset = reloc.r_address,
        },
        .page_op = undefined,
    };
}

fn parsePage21Reloc(reloc: macho.relocation_info, addend: ?u32, page_reloc: *PageReloc) void {
    assert(reloc.r_length == 2);
    assert(reloc.r_pcrel == 1);

    const kind: PageReloc.Kind = switch (@intToEnum(macho.reloc_type_arm64, reloc.r_type)) {
        .ARM64_RELOC_PAGE21 => .Normal,
        .ARM64_RELOC_GOT_LOAD_PAGE21 => .Got,
        .ARM64_RELOC_TLVP_LOAD_PAGE21 => .Tlv,
        else => unreachable,
    };
    const target_type: PageReloc.TargetType = if (reloc.r_extern == 1) .Symbol else .Section;

    assert(kind == page_reloc.kind);
    assert(target_type == page_reloc.target_type);

    if (reloc.r_extern == 1) {
        assert(reloc.r_symbolnum == page_reloc.target);
    } else {
        assert(reloc.r_symbolnum - 1 == page_reloc.target);
    }

    page_reloc.page_op = .{
        .addend = addend,
        .offset = reloc.r_address,
    };
}

pub fn parseRelocs(self: *Object, sect_id: u16) !void {
    const seg = self.load_commands.items[self.segment_cmd_index.?].Segment;
    const sect = seg.sections.items[sect_id];

    if (sect.nreloc == 0) return;

    var raw_relocs = try self.allocator.alloc(u8, @sizeOf(macho.relocation_info) * sect.nreloc);
    defer self.allocator.free(raw_relocs);
    _ = try self.file.?.preadAll(raw_relocs, sect.reloff);
    const relocs = mem.bytesAsSlice(macho.relocation_info, raw_relocs);

    var fifo = std.fifo.LinearFifo(PageReloc, .Dynamic).init(self.allocator);
    defer fifo.deinit();

    var i: usize = 0;
    while (i < relocs.len) : (i += 1) {
        const reloc = relocs[i];
        const rel_type = @intToEnum(macho.reloc_type_arm64, reloc.r_type);

        log.warn("{s}", .{rel_type});
        log.warn("    | offset = {}", .{reloc.r_address});
        log.warn("    | PC = {}", .{reloc.r_pcrel == 1});
        log.warn("    | length = {}", .{reloc.r_length});
        log.warn("    | symbolnum = {}", .{reloc.r_symbolnum});

        switch (rel_type) {
            .ARM64_RELOC_ADDEND => {
                const next_reloc = relocs[i + 1];
                i += 1;

                log.warn("{s}", .{@intToEnum(macho.reloc_type_arm64, next_reloc.r_type)});
                log.warn("    | offset = {}", .{next_reloc.r_address});
                log.warn("    | PC = {}", .{next_reloc.r_pcrel == 1});
                log.warn("    | length = {}", .{next_reloc.r_length});
                log.warn("    | symbolnum = {}", .{next_reloc.r_symbolnum});

                switch (@intToEnum(macho.reloc_type_arm64, next_reloc.r_type)) {
                    .ARM64_RELOC_PAGE21, .ARM64_RELOC_GOT_LOAD_PAGE21, .ARM64_RELOC_TLVP_LOAD_PAGE21 => {
                        var page_reloc = fifo.readItem() orelse unreachable;
                        parsePage21Reloc(next_reloc, reloc.r_symbolnum, &page_reloc);

                        log.warn("    | emitting {}", .{page_reloc});
                        // TODO save the combined reloc
                    },
                    .ARM64_RELOC_PAGEOFF12, .ARM64_RELOC_GOT_LOAD_PAGEOFF12, .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => {
                        var page_reloc = parsePageOff12Reloc(next_reloc, reloc.r_symbolnum);
                        try fifo.writeItem(page_reloc);
                    },
                    else => {
                        log.err("unexpected reloc type after ADDEND: expected either PAGE21 or PAGEOFF12, got {s}", .{@intToEnum(
                            macho.reloc_type_arm64,
                            reloc.r_type,
                        )});
                        // TODO we probably should continue parsing the relocs anyway reporting any other errors along the way?
                        return error.InvalidRelocAfterAddend;
                    },
                }
            },
            .ARM64_RELOC_PAGEOFF12, .ARM64_RELOC_GOT_LOAD_PAGEOFF12, .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => {
                var page_reloc = parsePageOff12Reloc(reloc, null);
                try fifo.writeItem(page_reloc);
            },
            .ARM64_RELOC_PAGE21, .ARM64_RELOC_GOT_LOAD_PAGE21, .ARM64_RELOC_TLVP_LOAD_PAGE21 => {
                var page_reloc = fifo.readItem() orelse unreachable;
                parsePage21Reloc(reloc, null, &page_reloc);

                log.warn("    | emitting {}", .{page_reloc});
                // TODO save the combined reloc

            },
            else => {},
        }
    }

    assert(fifo.count == 0);
}

pub fn parseSymtab(self: *Object) !void {
    const symtab_cmd = self.load_commands.items[self.symtab_cmd_index.?].Symtab;

    var symtab = try self.allocator.alloc(u8, @sizeOf(macho.nlist_64) * symtab_cmd.nsyms);
    defer self.allocator.free(symtab);

    _ = try self.file.?.preadAll(symtab, symtab_cmd.symoff);
    try self.symtab.ensureCapacity(self.allocator, symtab_cmd.nsyms);

    var stream = std.io.fixedBufferStream(symtab);
    var reader = stream.reader();

    while (true) {
        const symbol = reader.readStruct(macho.nlist_64) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        const tag: Symbol.Tag = tag: {
            if (Symbol.isLocal(symbol)) {
                if (Symbol.isStab(symbol))
                    break :tag .Stab
                else
                    break :tag .Local;
            } else if (Symbol.isGlobal(symbol)) {
                if (Symbol.isWeakDef(symbol))
                    break :tag .Weak
                else
                    break :tag .Strong;
            } else {
                break :tag .Undef;
            }
        };
        self.symtab.appendAssumeCapacity(.{
            .tag = tag,
            .inner = symbol,
        });
    }

    var strtab = try self.allocator.alloc(u8, symtab_cmd.strsize);
    defer self.allocator.free(strtab);

    _ = try self.file.?.preadAll(strtab, symtab_cmd.stroff);
    try self.strtab.appendSlice(self.allocator, strtab);
}

pub fn getString(self: *const Object, str_off: u32) []const u8 {
    assert(str_off < self.strtab.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.strtab.items.ptr + str_off));
}

pub fn readSection(self: Object, allocator: *Allocator, index: u16) ![]u8 {
    const seg = self.load_commands.items[self.segment_cmd_index.?].Segment;
    const sect = seg.sections.items[index];
    var buffer = try allocator.alloc(u8, sect.size);
    _ = try self.file.?.preadAll(buffer, sect.offset);
    return buffer;
}

pub fn readDataInCode(self: *Object) !void {
    const index = self.data_in_code_cmd_index orelse return;
    const data_in_code = self.load_commands.items[index].LinkeditData;

    var buffer = try self.allocator.alloc(u8, data_in_code.datasize);
    defer self.allocator.free(buffer);

    _ = try self.file.?.preadAll(buffer, data_in_code.dataoff);

    var stream = io.fixedBufferStream(buffer);
    var reader = stream.reader();
    while (true) {
        const dice = reader.readStruct(macho.data_in_code_entry) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        try self.data_in_code_entries.append(self.allocator, dice);
    }
}
