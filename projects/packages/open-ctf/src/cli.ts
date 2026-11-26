#!/usr/bin/env node
/**
 * Command-line assembly only.
 *
 * Every command parses arguments, constructs the `OpenCTF` API and renders its
 * result; binary semantics stay in the built-in engine. Help text and errors
 * come from `@wae/commander`, so the CLI does not grow its own parser.
 */

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { createCli } from '@wae/commander';

import { OpenCTF, capabilities, cyclic, decodeJwt, parseUrl } from './api.js';
import { runGui } from './gui.js';
import type {
    BinaryInfo,
    Capabilities,
    CarveOptions,
    CarveReport,
    CaesarOptions,
    CaesarReport,
    CertificatesReport,
    CyclicOptions,
    CyclicReport,
    DebugReport,
    DecodeOptions,
    DecodeReport,
    DiffReport,
    DisassemblyReport,
    DumpOptions,
    DumpReport,
    ElfDynamicReport,
    ElfNotesReport,
    ElfSegmentsReport,
    ElfStaticSymbolsReport,
    EncodedStringsReport,
    EntropyReport,
    ExportsReport,
    FindOptions,
    FindReport,
    GadgetOptions,
    GadgetsReport,
    HashOptions,
    HashReport,
    ImportsReport,
    InflateFormat,
    InflateOptions,
    InflateReport,
    JwtReport,
    NsisReport,
    AsarReport,
    SevenZReport,
    PyInstallerReport,
    PackerReport,
    PcapOptions,
    PcapReport,
    PngOptions,
    PngReport,
    UrlReport,
    UnpackFormat,
    UnpackOptions,
    DisassemblyFormat,
    PycReport,
    OverlayReport,
    MachOReport,
    MachOCodeSignatureReport,
    MachOSlicesReport,
    MachOSliceExtraction,
    MachOExportsReport,
    MachOEncryptionReport,
    MachOChainedFixupsReport,
    MachOBindingsReport,
    MachOFunctionStartsReport,
    MachOSymbolsReport,
    MitigationsReport,
    PeBoundImportsReport,
    PeDelayImportsReport,
    PeExceptionReport,
    PeRichHeaderReport,
    PeLoadConfigReport,
    PeTlsReport,
    ProbeOptions,
    ProbeReport,
    RelocationsReport,
    ResourcesReport,
    SearchOptions,
    SearchReport,
    Section,
    StringEncoding,
    SymbolsReport,
    TauriAssetsOptions,
    TauriAssetsReport,
    VersionReport,
    XorOptions,
    XorReport,
} from './types.js';

const here = path.dirname(fileURLToPath(import.meta.url));

const cli = createCli('open-ctf').locales(path.join(here, '..', 'locales')).intro('cli.intro');

// Exported for contract audits that import the built entry to inspect the
// command tree. Nothing runs until the file is executed as the program entry.
export { cli };

interface ParsedOptions {
    readonly _?: readonly string[];
    readonly [key: string]: unknown;
}

const text = (options: ParsedOptions, key: string): string | undefined =>
    typeof options[key] === 'string' ? (options[key] as string) : undefined;

const input = (options: ParsedOptions): string | undefined => options._?.[0];

function parseNumber(value: string | undefined): number | undefined {
    if (value === undefined || value.trim().length === 0) {
        return undefined;
    }
    const trimmed = value.trim();
    const parsed = /^0x/i.test(trimmed) ? Number.parseInt(trimmed.slice(2), 16) : Number.parseInt(trimmed, 10);
    return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

function hex(value: number): string {
    return `0x${value.toString(16)}`;
}

function describeCapabilities(matrix: Capabilities): string {
    const formats = Object.entries(matrix.formats).map(([name, state]) => `${name}=${state}`);
    const features = Object.entries(matrix.features)
        .filter(([, state]) => state === 'supported')
        .map(([name]) => name);
    const missing = Object.entries(matrix.unsupported).map(([name, state]) => `${name}=${state}`);
    return [
        `engine: ${matrix.engine.package} ${matrix.engine.version}`,
        `formats: ${formats.join(', ')}`,
        `features: ${features.length > 0 ? features.join(', ') : 'none supported'}`,
        `unsupported: ${missing.length > 0 ? missing.join(', ') : 'nothing declared'}`,
    ].join('\n');
}

function describeInfo(info: BinaryInfo): string {
    const lines = [
        info.path,
        `format: ${info.format}${info.magic ? ` (${info.magic})` : ''} · arch ${info.architecture} · size ${info.size} bytes`,
        `sections: ${info.sectionCount} · hash: ${info.hash}`,
    ];
    if (info.entry !== null) {
        const rva = info.entryRva === null ? '' : ` (RVA ${hex(info.entryRva)})`;
        lines.push(`entry: ${hex(info.entry)}${rva}`);
    }
    if (info.imageBase !== null) {
        lines.push(`image base: ${hex(info.imageBase)}`);
    }
    if (info.commandCount !== null) {
        lines.push(`mach-o: cpuType=${hex(info.cpuType ?? 0)} fileType=${info.fileType ?? 0} commands=${info.commandCount}`);
    }
    return lines.join('\n');
}

function accessFlags(section: Section): string {
    return `${section.readable ? 'r' : '-'}${section.writable ? 'w' : '-'}${section.executable ? 'x' : '-'}`;
}

function describeSections(sections: readonly Section[]): string {
    if (sections.length === 0) {
        return 'no sections';
    }
    const lines = [`${sections.length} section(s)`];
    for (const section of sections) {
        lines.push(
            `  ${(section.name || '(unnamed)').padEnd(12)} vaddr=${hex(section.virtualAddress)} vsize=${hex(section.virtualSize)} file=${hex(section.rawPointer)}+${hex(section.rawSize)} ${accessFlags(section)}`,
        );
    }
    return lines.join('\n');
}

function describeStrings(report: EncodedStringsReport): string {
    const header = `${report.hits.length} of ${report.total} ${report.encoding} string(s)${report.truncated ? ' (truncated)' : ''}`;
    if (report.hits.length === 0) {
        return `${header}\n  no printable runs matched the minimum length`;
    }
    const lines = [header];
    const tagEncoding = report.encoding === 'both';
    for (const hit of report.hits) {
        const tag = tagEncoding ? `  ${hit.encoding.padEnd(7)}` : '';
        lines.push(`  ${hex(hit.offset).padStart(10)}  ${String(hit.length).padStart(4)}${tag}  ${hit.value}`);
    }
    return lines.join('\n');
}

function entriesHeader(count: number, total: number, noun: string, truncated: boolean): string {
    return `${count} of ${total} ${noun}${truncated ? ' (truncated)' : ''}`;
}

function describeImports(report: ImportsReport): string {
    const header = entriesHeader(report.entries.length, report.total, 'import(s)', report.truncated);
    if (report.entries.length === 0) {
        return `${header}\n  no imports`;
    }
    const lines = [header];
    for (const entry of report.entries) {
        const symbol = entry.name ?? `#${entry.ordinal ?? '?'}`;
        const module = entry.module.length > 0 ? `${entry.module}!` : '';
        const address = entry.address === null ? '' : `  ${hex(entry.address)}`;
        lines.push(`  ${`${module}${symbol}`.padEnd(40)}${address}`);
    }
    return lines.join('\n');
}

function describeExports(report: ExportsReport): string {
    const header = entriesHeader(report.entries.length, report.total, 'export(s)', report.truncated);
    if (report.entries.length === 0) {
        return `${header}\n  no exports`;
    }
    const lines = [header];
    for (const entry of report.entries) {
        const symbol = entry.name ?? `#${entry.ordinal ?? '?'}`;
        const address = entry.address === null ? '' : `  ${hex(entry.address)}`;
        const forwarder = entry.forwarder === null ? '' : `  -> ${entry.forwarder}`;
        lines.push(`  ${symbol.padEnd(40)}${address}${forwarder}`);
    }
    return lines.join('\n');
}

function describeSymbols(report: SymbolsReport): string {
    const header = entriesHeader(report.entries.length, report.total, 'symbol(s)', report.truncated);
    if (report.entries.length === 0) {
        return `${header}\n  no symbols`;
    }
    const lines = [header];
    for (const entry of report.entries) {
        const section = entry.section === null ? '' : `  (${entry.section})`;
        lines.push(`  ${hex(entry.address).padStart(12)}  ${entry.kind.padEnd(9)} ${entry.binding.padEnd(6)} ${entry.name}${section}`);
    }
    return lines.join('\n');
}

function describeDebug(report: DebugReport): string {
    const header = entriesHeader(report.entries.length, report.total, 'debug entry(ies)', report.truncated);
    if (report.entries.length === 0) {
        return `${header}\n  no debug directory entries`;
    }
    const lines = [header];
    for (const entry of report.entries) {
        lines.push(
            `  ${entry.debugType.padEnd(20)} ts=${hex(entry.timestamp)} v${entry.majorVersion}.${entry.minorVersion} size=${entry.sizeOfData} raw=${hex(entry.pointerToRawData)} rva=${hex(entry.addressOfRawData)}`,
        );
        if (entry.codeView !== null) {
            const record = entry.codeView;
            const identity =
                record.guid !== null
                    ? `guid=${record.guid}`
                    : `offset=${hex(record.offset ?? 0)} timestamp=${hex(record.timestamp ?? 0)}`;
            lines.push(`    ${record.signature} age=${record.age} ${identity} path=${record.path}`);
        }
    }
    return lines.join('\n');
}

function describeVersion(report: VersionReport): string {
    if (!report.present) {
        return 'no RT_VERSION resource';
    }
    const lines: string[] = [];
    if (report.fixed !== null) {
        lines.push(`file version: ${report.fixed.fileVersion}`);
        lines.push(`product version: ${report.fixed.productVersion}`);
        lines.push(
            `flags: ${hex(report.fixed.fileFlags)} / mask ${hex(report.fixed.fileFlagsMask)} · os ${hex(report.fixed.fileOs)} · type ${report.fixed.fileType}.${report.fixed.fileSubtype}`,
        );
    }
    if (report.note !== null) {
        lines.push(`note: ${report.note}`);
    }
    lines.push(`${report.strings.length} of ${report.total} string(s)${report.truncated ? ' (truncated)' : ''}`);
    for (const entry of report.strings) {
        lines.push(`  ${entry.key.padEnd(22)} ${entry.value}  (lang ${hex(entry.languageId)}, cp ${hex(entry.codepage)})`);
    }
    return lines.join('\n');
}

function describeResources(report: ResourcesReport): string {
    if (!report.present) {
        return 'no resource directory';
    }
    const header = entriesHeader(report.resources.length, report.total, 'resource(s)', report.truncated);
    if (report.resources.length === 0) {
        return `${header}\n  no resources`;
    }
    const lines = [header];
    for (const entry of report.resources) {
        lines.push(
            `  ${entry.resourceType.padEnd(14)} ${entry.name.padEnd(16)} lang ${hex(entry.language)} rva ${hex(entry.dataRva)} size ${hex(entry.size)}`,
        );
    }
    return lines.join('\n');
}

function describeException(report: PeExceptionReport): string {
    if (!report.present) {
        return 'no exception directory';
    }
    const size = report.entrySize === null ? 'unknown size' : `${report.entrySize}-byte entries`;
    const header = entriesHeader(report.functions.length, report.total, 'runtime function(s)', report.truncated);
    const lines = [`${header} · ${report.machineName} · ${report.entryFormat} (${size})`];
    for (const entry of report.functions) {
        const end = entry.endAddress === 0 ? '' : `-${hex(entry.endAddress)}`;
        const unwind = entry.unwind;
        const detail =
            unwind === null
                ? `unwind ${hex(entry.unwindInfo)}`
                : `unwind ${hex(entry.unwindInfo)} v${unwind.version} prolog ${unwind.prologSize} codes ${unwind.codeCount}${
                      unwind.flagNames.length === 0 ? '' : ` ${unwind.flagNames.join('|')}`
                  }`;
        lines.push(`  ${hex(entry.beginAddress)}${end} · ${detail}`);
    }
    return lines.join('\n');
}

function describeDelayImports(report: PeDelayImportsReport): string {
    if (!report.present) {
        return 'no delay-import directory';
    }
    const header = entriesHeader(report.modules.length, report.totalModules, 'delay module(s)', report.truncated);
    const lines = [`${header} · ${report.totalThunks} thunk(s)`];
    for (const module of report.modules) {
        const name = module.name.length === 0 ? '(unresolved)' : module.name;
        lines.push(`  ${name} · ts ${hex(module.timestamp)} · int ${hex(module.intRva)} · iat ${hex(module.iatRva)}`);
        for (const thunk of module.thunks) {
            const symbol = thunk.name ?? `#${thunk.ordinal ?? '?'}`;
            const hint = thunk.hint === null ? '' : ` hint ${thunk.hint}`;
            const slot = thunk.iatRva === null ? '' : `  iat ${hex(thunk.iatRva)}`;
            lines.push(`    ${hex(thunk.intRva)}  ${symbol}${hint}${slot}`);
        }
    }
    return lines.join('\n');
}

function describeBoundImports(report: PeBoundImportsReport): string {
    if (!report.present) {
        return 'no bound-import directory';
    }
    const header = entriesHeader(report.modules.length, report.totalModules, 'bound module(s)', report.truncated);
    const lines = [`${header} · ${report.totalForwarders} forwarder(s)`];
    for (const module of report.modules) {
        const name = module.name.length === 0 ? '(unresolved)' : module.name;
        lines.push(`  ${name} · ts ${hex(module.timestamp)} · name offset ${hex(module.offsetModuleName)}`);
        for (const forwarder of module.forwarders) {
            const refName = forwarder.name.length === 0 ? '(unresolved)' : forwarder.name;
            lines.push(`    → ${refName} · ts ${hex(forwarder.timestamp)} · name offset ${hex(forwarder.offsetModuleName)}`);
        }
    }
    return lines.join('\n');
}

function describeRichHeader(report: PeRichHeaderReport): string {
    if (!report.present) {
        return 'no Rich header';
    }
    const header = entriesHeader(report.entries.length, report.total, 'entry(ies)', report.truncated);
    const lines = [`${header} · key ${hex(report.key)} · DanS ${hex(report.dansOffset)} · Rich ${hex(report.richOffset)}`];
    for (const entry of report.entries) {
        const name = entry.name === null ? '' : ` · ${entry.name}`;
        lines.push(`  ${hex(entry.compId)} · build ${entry.build} · count ${entry.count}${name}`);
    }
    return lines.join('\n');
}

function describeStaticSymbols(report: ElfStaticSymbolsReport): string {
    if (!report.present) {
        return 'no .symtab section';
    }
    const header = entriesHeader(report.symbols.length, report.total, 'symbol(s)', report.truncated);
    const lines = [`${header} · ${report.is64 ? 'ELF64' : 'ELF32'}`];
    for (const symbol of report.symbols) {
        const name = symbol.name.length === 0 ? '(null)' : symbol.name;
        lines.push(
            `  ${hex(symbol.value)} · size ${symbol.size} · ${symbol.symbolType}/${symbol.binding}` +
                `/${symbol.visibility} · ${symbol.section} · ${name}`,
        );
    }
    return lines.join('\n');
}

function describeRelocations(report: RelocationsReport): string {
    if (!report.present) {
        return 'no base relocations';
    }
    const header = entriesHeader(report.blocks.length, report.totalBlocks, 'block(s)', report.truncated);
    const lines = [
        `${header} · ${report.totalEntries} fixup(s)${report.truncated ? ' (truncated)' : ''}`,
        `kinds: ${report.kinds.map((entry) => `${entry.kind}=${entry.count}`).join(', ') || 'none'}`,
    ];
    for (const block of report.blocks) {
        const kinds = block.kinds.map((entry) => `${entry.kind}=${entry.count}`).join(' ');
        lines.push(`  page ${hex(block.pageRva)} · ${block.entries} entr${block.entries === 1 ? 'y' : 'ies'} · ${kinds}`);
    }
    return lines.join('\n');
}

function describeDynamic(report: ElfDynamicReport): string {
    const lines = [`interpreter: ${report.interpreter ?? 'none'}`];
    if (!report.present) {
        lines.push('no PT_DYNAMIC segment (static image)');
        return lines.join('\n');
    }
    lines.push(`soname: ${report.soname ?? 'none'}`);
    lines.push(`${report.needed.length} needed librar${report.needed.length === 1 ? 'y' : 'ies'}${report.truncated ? ' (truncated)' : ''}`);
    for (const name of report.needed) {
        lines.push(`  ${name}`);
    }
    if (report.rpath.length > 0) {
        lines.push(`rpath: ${report.rpath.join(':')}`);
    }
    if (report.runpath.length > 0) {
        lines.push(`runpath: ${report.runpath.join(':')}`);
    }
    lines.push(`dynamic entries: ${report.dynamicEntries}`);
    return lines.join('\n');
}

function describeSegments(report: ElfSegmentsReport): string {
    if (!report.present) {
        return 'no program header table';
    }
    const header = entriesHeader(report.segments.length, report.total, 'segment(s)', report.truncated);
    const lines = [`${header} · ${report.is64 ? '64-bit' : '32-bit'}`];
    for (const segment of report.segments) {
        lines.push(
            `  ${String(segment.index).padStart(2)} ${segment.segmentType.padEnd(18)} ${hex(segment.offset)} vaddr ${hex(segment.virtualAddress)} filesz ${hex(segment.fileSize)} memsz ${hex(segment.memorySize)} ${segment.flagText || '---'} align ${segment.alignment}`,
        );
    }
    return lines.join('\n');
}

function describeNotes(report: ElfNotesReport): string {
    if (!report.present) {
        return 'no note segments or sections';
    }
    const header = entriesHeader(report.notes.length, report.total, 'note(s)', report.truncated);
    const lines = [
        `${header} · source ${report.source ?? 'unknown'}`,
        `build id: ${report.buildId ?? 'none'}`,
    ];
    if (report.abiTag !== null) {
        const tag = report.abiTag;
        lines.push(`abi tag: ${tag.os} ${tag.major}.${tag.minor}.${tag.subminor}`);
    }
    for (const note of report.notes) {
        lines.push(`  ${note.owner.padEnd(10)} ${note.noteType.padEnd(24)} ${note.descriptionSize} byte(s)  ${note.description}`);
    }
    for (const property of report.properties) {
        lines.push(`  property ${property.propertyType} (${property.dataSize} bytes) ${property.data}`);
    }
    return lines.join('\n');
}

function describeTls(report: PeTlsReport): string {
    if (!report.present) {
        return 'no TLS directory';
    }
    const lines = [
        `directory ${hex(report.directoryRva)} (${report.directorySize} bytes, ${report.is64 ? '64-bit' : '32-bit'} layout)`,
        `raw data ${hex(report.rawDataStart)}..${hex(report.rawDataEnd)} · zero fill ${report.sizeOfZeroFill} bytes`,
        `index ${hex(report.indexAddress)} · callbacks ${hex(report.callbacksAddress)}${report.callbacksRva === null ? '' : ` (RVA ${hex(report.callbacksRva)})`}`,
        `characteristics ${hex(report.characteristics)}`,
        `${report.callbacks.length} callback(s)${report.truncated ? ' (truncated)' : ''}`,
    ];
    for (const callback of report.callbacks) {
        const rva = callback.rva === null ? '' : ` rva ${hex(callback.rva)}`;
        const offset = callback.offset === null ? '' : ` file ${hex(callback.offset)}`;
        lines.push(`  ${hex(callback.address)}${rva}${offset}`);
    }
    return lines.join('\n');
}

function describeCodeSignature(report: MachOCodeSignatureReport): string {
    if (!report.present) {
        return 'no embedded code signature';
    }
    const lines = [
        `blob ${hex(report.dataOffset)} (${report.dataSize} bytes) · ${report.magic ?? 'unknown'} · ${report.blobCount ?? 0} entr${(report.blobCount ?? 0) === 1 ? 'y' : 'ies'}${report.truncated ? ' (truncated)' : ''}`,
        `blobs: ${report.blobTypes.length === 0 ? 'none' : report.blobTypes.join(', ')}`,
    ];
    const code = report.codeDirectory;
    if (code !== null) {
        lines.push(
            `code directory v0x${code.version.toString(16)} · ${code.hashType} · page ${code.pageSize} · limit ${hex(code.codeLimit)}`,
        );
        lines.push(`identifier ${code.identifier || '(none)'} · team ${code.teamId ?? '(none)'}`);
        lines.push(
            `slots ${code.codeSlots} code / ${code.specialSlots} special${code.flagText.length === 0 ? '' : ` · ${code.flagText.join(' | ')}`}`,
        );
    }
    return lines.join('\n');
}

function describeLoadConfig(report: PeLoadConfigReport): string {
    if (!report.present) {
        return 'no load configuration directory';
    }
    const lines = [
        `size ${report.size} bytes · ${report.is64 ? '64-bit' : '32-bit'} layout${report.truncated ? ' (truncated)' : ''}`,
        `security cookie ${hex(report.securityCookie)} · SEH table ${hex(report.seHandlerTable)} (${report.seHandlerCount} entries)`,
        `CFG table ${hex(report.guardCfFunctionTable)} (${report.guardCfFunctionCount} entries) · check ${hex(report.guardCfCheckFunctionPointer)}`,
        `guard flags ${hex(report.guardFlags)}${report.guardFlagsText.length === 0 ? '' : ` · ${report.guardFlagsText.join(' | ')}`}`,
        `code integrity flags ${hex(report.codeIntegrity.flags)} · catalog ${report.codeIntegrity.catalog} @ ${hex(report.codeIntegrity.catalogOffset)}`,
    ];
    return lines.join('\n');
}

function describeCertificates(report: CertificatesReport): string {
    if (!report.present) {
        return 'no attribute certificate table';
    }
    const header = entriesHeader(report.certificates.length, report.total, 'certificate(s)', report.truncated);
    const lines = [`${header} · directory ${report.directorySize} bytes`];
    if (report.certificates.length === 0) {
        lines.push('  no certificates');
    }
    for (const certificate of report.certificates) {
        const shape = certificate.pkcs7 ? ' · pkcs7' : '';
        lines.push(
            `  ${hex(certificate.offset)} ${certificate.revision} ${certificate.certificateType} ${certificate.payloadSize} byte(s)${shape}`,
        );
    }
    return lines.join('\n');
}

function describeMachOSliceExtraction(report: MachOSliceExtraction): string {
    return `wrote slice ${report.index} (${report.architecture}) at ${hex(report.offset)} (${report.size} bytes) to ${report.output}`;
}

function describeMitigations(report: MitigationsReport): string {
    const on = (value: boolean) => (value ? 'yes' : 'no');
    const lines = [
        `dll characteristics ${hex(report.dllCharacteristics)}`,
        `  aslr              ${on(report.aslr)}`,
        `  high-entropy va   ${on(report.highEntropyVa)}`,
        `  dep (nx)          ${on(report.dep)}`,
        `  cfg               ${on(report.cfg)}`,
        `  force integrity   ${on(report.forceIntegrity)}`,
        `  no seh            ${on(report.noSeh)}`,
        `  terminal server   ${on(report.terminalServerAware)}`,
        `  relocations       ${report.relocationsPresent ? 'present' : 'stripped'}`,
        `  certificate table ${report.signed ? 'present (not verified)' : 'absent'}`,
        `  gs cookie         ${report.securityCookie === null ? 'no load config' : on(report.securityCookie)}`,
    ];
    if (report.guardFlags !== null) {
        lines.push(`  guard flags       ${hex(report.guardFlags)}`);
    }
    if (report.writableExecutableSections.length === 0) {
        lines.push('  w+x sections      none');
    } else {
        lines.push(`  w+x sections      ${report.writableExecutableSections.map((section) => section.name).join(', ')}`);
    }
    return lines.join('\n');
}

function describeMachO(report: MachOReport): string {
    const bits = report.is64 ? 64 : 32;
    const lines = [
        `mach-o ${bits}-bit ${report.endian}-endian · ${report.architecture} · ${report.kind} (fileType ${report.fileType})`,
        `commands: ${report.commandCount} (${report.sizeOfCommands} bytes) · flags ${hex(report.flags)}`,
    ];
    if (report.uuid !== null) {
        lines.push(`uuid: ${report.uuid}`);
    }
    if (report.platform !== null) {
        const sdk = report.sdk === null ? '' : ` · sdk ${report.sdk}`;
        lines.push(`platform: ${report.platform}${report.minOs === null ? '' : ` · min ${report.minOs}`}${sdk}`);
    }
    if (report.entryOffset !== null) {
        const address = report.entryAddress === null ? '' : ` -> ${hex(report.entryAddress)}`;
        lines.push(`entry: file ${hex(report.entryOffset)}${address}`);
    }
    if (report.dylibs.length > 0) {
        lines.push(`dylibs: ${report.dylibs.length}`);
        for (const dylib of report.dylibs) {
            lines.push(`  ${dylib.kind.padEnd(9)} ${dylib.name} (${dylib.currentVersion})`);
        }
    }
    if (report.segments.length > 0) {
        lines.push(`segments: ${report.segments.length}`);
        for (const segment of report.segments) {
            const access = `${segment.readable ? 'r' : '-'}${segment.writable ? 'w' : '-'}${segment.executable ? 'x' : '-'}`;
            lines.push(
                `  ${segment.name.padEnd(12)} vm=${hex(segment.vmAddress)}+${hex(segment.vmSize)} file=${hex(segment.fileOffset)}+${hex(segment.fileSize)} ${access}`,
            );
        }
    }
    if (report.sections.length > 0) {
        lines.push(`sections: ${report.sections.length}`);
        for (const section of report.sections) {
            const access = `${section.readable ? 'r' : '-'}${section.writable ? 'w' : '-'}${section.executable ? 'x' : '-'}`;
            lines.push(
                `  ${`${section.segment},${section.name}`.padEnd(24)} addr=${hex(section.address)} size=${hex(section.size)} file=${hex(section.fileOffset)} ${access}`,
            );
        }
    }
    return lines.join('\n');
}

function describeMachOSymbols(report: MachOSymbolsReport): string {
    const header = entriesHeader(report.symbols.length, report.total, 'Mach-O symbol(s)', report.truncated);
    if (report.symbols.length === 0) {
        return `${header}\n  no symbols`;
    }
    const lines = [header, `string table: ${report.stringTableSize} bytes`];
    for (const symbol of report.symbols) {
        const flags = `${symbol.external ? 'ext' : 'int'}${symbol.debug ? ',dbg' : ''}`;
        const section = symbol.section === null ? '' : `  sect ${symbol.section}`;
        lines.push(
            `  ${hex(symbol.address).padStart(12)}  ${symbol.kind.padEnd(9)} ${flags.padEnd(7)} ${symbol.name}${section}`,
        );
    }
    return lines.join('\n');
}

function describeMachOExports(report: MachOExportsReport): string {
    if (!report.present) {
        return 'no dyld export trie';
    }
    const lines = [entriesHeader(report.exports.length, report.total, 'export(s)', report.truncated)];
    for (const entry of report.exports) {
        const flags = entry.flagNames.length === 0 ? '' : ` ${entry.flagNames.join('|')}`;
        const detail =
            entry.address === null ? `other ${entry.other ?? 0}` : `address ${hex(entry.address)}`;
        lines.push(`  ${entry.name} · ${detail}${flags}`);
    }
    return lines.join('\n');
}

function describeMachOEncryption(report: MachOEncryptionReport): string {
    if (!report.present) {
        return 'no LC_ENCRYPTION_INFO command';
    }
    const kind = report.is64 ? 'LC_ENCRYPTION_INFO_64' : 'LC_ENCRYPTION_INFO';
    const state = report.encrypted ? 'encrypted' : 'clear';
    return `${kind} · ${state} · cryptid ${report.cryptId} · offset ${hex(report.cryptOffset)} · size ${hex(report.cryptSize)}`;
}

function describeMachOChainedFixups(report: MachOChainedFixupsReport): string {
    if (!report.present) {
        return 'no LC_DYLD_CHAINED_FIXUPS command';
    }
    const header = entriesHeader(report.imports.length, Number(report.header?.importsCount ?? 0), 'import(s)', report.truncated);
    const lines = [header];
    if (report.header !== null) {
        lines.push(
            `chain data ${hex(report.dataOffset)} · ${hex(report.dataSize)} · imports format ${report.header.importsFormat} · symbols format ${report.header.symbolsFormat}`,
        );
    }
    lines.push(`starts: ${report.startsInImage ?? 0} segment(s), ${report.startsInSegmentCount} populated`);
    for (const entry of report.imports) {
        const flags = [entry.weakImport ? 'weak' : '', entry.addend === null ? '' : `addend ${entry.addend}`]
            .filter((flag) => flag !== '')
            .join(' ');
        const suffix = flags === '' ? '' : ` (${flags})`;
        lines.push(`  ${entry.name === '' ? `#${entry.nameOffset}` : entry.name} · ordinal ${entry.libOrdinal}${suffix}`);
    }
    return lines.join('\n');
}

function describeMachOBindings(report: MachOBindingsReport): string {
    if (!report.present) {
        return 'no LC_DYLD_INFO bind opcodes';
    }
    const header = entriesHeader(report.bindings.length, report.total, 'binding(s)', report.truncated);
    if (report.bindings.length === 0) {
        return `${header}\n  no bindings`;
    }
    const lines = [header];
    for (const binding of report.bindings) {
        const flags = [binding.weak ? 'weak' : '', binding.addend === 0 ? '' : `addend ${binding.addend}`]
            .filter((flag) => flag !== '')
            .join(' ');
        const suffix = flags === '' ? '' : ` (${flags})`;
        const segment = binding.segment === '' ? '' : ` · ${binding.segment}`;
        const dylib = binding.dylib === '' ? '' : ` · ${binding.dylib}`;
        lines.push(
            `  ${binding.stream.padEnd(5)} ${hex(binding.address).padStart(12)}  ${binding.bindType.padEnd(13)} ${binding.symbol || '(none)'}${dylib}${segment}${suffix}`,
        );
    }
    return lines.join('\n');
}

function describeMachOFunctionStarts(report: MachOFunctionStartsReport): string {
    const header = entriesHeader(report.addresses.length, report.total, 'function start(s)', report.truncated);
    const lines = [header, `image base: ${hex(report.imageBase)}`];
    for (const address of report.addresses) {
        lines.push(`  ${hex(address)}`);
    }
    return lines.join('\n');
}

function describeMachOSlices(report: MachOSlicesReport): string {
    if (report.slices.length === 0) {
        return 'no architecture slices';
    }
    const layout = report.isFat64 ? 'fat_arch_64' : 'fat_arch';
    const lines = [`${report.slices.length} slice(s) · ${layout}`];
    for (const slice of report.slices) {
        const bits = slice.bits === null ? '' : ` ${slice.bits}-bit`;
        lines.push(
            `  [${slice.index}] ${slice.architecture.padEnd(6)} cpu=${hex(slice.cpuType)}/${hex(slice.cpuSubtype)}${bits} offset=${hex(slice.offset)} size=${hex(slice.size)} align=2^${slice.alignment}`,
        );
    }
    return lines.join('\n');
}

function describeDisassembly(report: DisassemblyReport): string {
    const header = `${report.instructions.length} instruction(s) · ${report.architecture} ${report.bitness}-bit · ${report.syntax} · start ${hex(report.startOffset)} @ ${hex(report.startAddress)}${report.truncated ? ' (truncated)' : ''}`;
    if (report.instructions.length === 0) {
        return `${header}\n  no instructions`;
    }
    const lines = [header];
    for (const instruction of report.instructions) {
        lines.push(
            `  ${hex(instruction.address).padStart(12)}  ${hex(instruction.offset).padStart(8)}  ${instruction.bytes.padEnd(18)}  ${instruction.text}`,
        );
    }
    return lines.join('\n');
}

function describeEntropy(report: EntropyReport): string {
    const lines = [`file ${report.fileSize} B · entropy ${report.fileEntropy.toFixed(4)} bits/byte`];
    lines.push(
        report.overlay === null
            ? 'overlay: none'
            : `overlay ${hex(report.overlay.offset)} + ${report.overlay.size} byte(s)`,
    );
    for (const section of report.sections) {
        lines.push(
            `  ${section.name.padEnd(12)} ${hex(section.offset).padStart(10)} + ${section.size} B  ${section.entropy.toFixed(4)}`,
        );
    }
    return lines.join('\n');
}

function describeOverlay(report: OverlayReport): string {
    if (!report.present) {
        return 'overlay: none';
    }
    const lines = [
        `overlay ${hex(report.offset)} + ${report.size} byte(s) · ${(report.ratio * 100).toFixed(1)}% of file · entropy ${report.entropy.toFixed(4)}`,
        `leading ${report.leadingMagic} · ${report.leadingKind}`,
    ];
    if (report.container !== null) {
        lines.push(`container ${report.container}${report.detail === null ? '' : ` · ${report.detail}`}`);
    }
    lines.push(`  ${report.signatures.length} signature(s)${report.truncated ? ' (truncated)' : ''}`);
    for (const signature of report.signatures) {
        lines.push(
            `  ${hex(signature.offset).padStart(10)}  ${signature.kind}${signature.detail === null ? '' : `  ${signature.detail}`}`,
        );
    }
    return lines.join('\n');
}

function describeInflate(report: InflateReport): string {
    const lines = [
        `inflate ${hex(report.offset)} · ${report.format} · ${report.outputBytes} byte(s) of ${report.inputBytes} input · ${report.status}`,
        `  limit ${report.limit}${report.truncated ? ' (truncated)' : ''}`,
        `  magic ${report.magic}`,
        `  ascii ${report.headAscii}`,
    ];
    if (report.output !== null) {
        lines.push(`  wrote ${report.outputBytes} byte(s) to ${report.output}`);
    }
    return lines.join('\n');
}

function describeNsis(report: NsisReport): string {
    const header = report.header;
    const lines = [
        `nsis ${hex(header.startOffset)} · ${header.method} · ${header.solid ? 'solid' : 'non-solid'} · header ${header.headerSize} B · arc ${header.arcSize} B`,
        `  strings ${report.stringChars} char(s) · ${report.unicode ? 'utf-16le' : 'latin-1'} · ${report.strings.length} rendered`,
        `  commands ${report.commandCount} · ${report.commands.length} rendered · files ${report.files.length}`,
    ];
    if (report.truncated) {
        lines.push('  (lists truncated)');
    }
    for (const file of report.files.slice(0, 20)) {
        lines.push(`  file #${file.index} ${file.output}${file.extracted !== null ? ` -> ${file.extracted}` : ''}`);
    }
    return lines.join('\n');
}

function describeAsar(report: AsarReport): string {
    const header = report.header;
    const lines = [
        `asar ${hex(header.startOffset)} · block ${header.blockSize} B · json ${header.stringSize} B · data ${hex(header.dataStart)}`,
        `  entries ${report.entryCount} · directories ${report.directoryCount} · packed ${report.packedBytes} B · ${report.entries.length} listed`,
    ];
    if (report.truncated) {
        lines.push('  (listing truncated)');
    }
    for (const entry of report.entries.slice(0, 40)) {
        const where = entry.unpacked ? 'unpacked' : hex(entry.offset ?? 0);
        lines.push(`  ${String(entry.size).padStart(10)} ${where.padStart(10)}  ${entry.path}${entry.extracted !== null ? ` -> ${entry.extracted}` : ''}`);
    }
    return lines.join('\n');
}

function describeSevenZ(report: SevenZReport): string {
    const lines = [
        `7z ${hex(report.startOffset)} · v${report.version} · ${report.entryCount} entry(s) · ${report.folderCount} folder(s) · ${report.totalUnpackSize} B unpacked`,
        `  methods ${report.methods.length === 0 ? 'none' : report.methods.join(', ')} · ${report.entries.length} listed`,
    ];
    if (report.truncated) {
        lines.push('  (listing truncated)');
    }
    for (const entry of report.entries.slice(0, 40)) {
        const kind = entry.isDir ? 'dir ' : entry.isAnti ? 'anti' : 'file';
        lines.push(
            `  ${kind} ${String(entry.size ?? 0).padStart(10)}  ${entry.name}${entry.extracted !== null ? ` -> ${entry.extracted}` : ''}`,
        );
    }
    return lines.join('\n');
}

function describePyInstaller(report: PyInstallerReport): string {
    if (report.archiveKind === 'pyz') {
        const lines = [
            `pyz ${hex(report.startOffset)} · ${report.python ?? 'unknown interpreter'} · magic ${report.pythonMagic === null ? '?' : hex(report.pythonMagic)} · ${report.entryCount} module(s)`,
        ];
        if (report.truncated) {
            lines.push('  (listing truncated)');
        }
        for (const module of report.modules.slice(0, 40)) {
            lines.push(
                `  ${module.isPackage ? 'pkg' : 'mod'} ${String(module.length).padStart(10)} ${hex(module.offset).padStart(10)}  ${module.name}${module.extracted !== null ? ` -> ${module.extracted}` : ''}`,
            );
        }
        return lines.join('\n');
    }
    const lines = [
        `carchive ${hex(report.startOffset)} · cookie ${hex(report.cookieOffset ?? 0)} · package ${report.packageLength ?? 0} B · TOC ${hex(report.tocOffset ?? 0)} + ${report.tocLength ?? 0} B`,
        `  version ${report.version ?? 'unknown'} · word ${report.versionWord ?? 0} · ${report.entryCount} entry(s) · ${report.entries.length} listed`,
    ];
    if (report.truncated) {
        lines.push('  (listing truncated)');
    }
    for (const entry of report.entries.slice(0, 40)) {
        lines.push(
            `  ${entry.kind.padEnd(6)} ${String(entry.length).padStart(10)} ${hex(entry.offset).padStart(10)}  ${entry.name} · ${entry.compressed ? 'zlib' : 'stored'}${entry.moduleCount !== null ? ` · ${entry.moduleCount} module(s)` : ''}${entry.extracted !== null ? ` -> ${entry.extracted}` : ''}`,
        );
        for (const module of entry.modules.slice(0, 20)) {
            lines.push(`      ${module.name}${module.extracted !== null ? ` -> ${module.extracted}` : ''}`);
        }
    }
    return lines.join('\n');
}

function describePyc(report: PycReport): string {
    const version = report.python ?? 'CPython marshal';
    const lines = [
        `pyc ${hex(report.startOffset)} · ${report.sourceFormat} · ${version} · table ${report.opcodeTable} · ${report.codeCount} code object(s) · ${report.instructionCount} instruction(s)${report.truncated ? ' (truncated)' : ''}`,
    ];
    for (const code of report.codes) {
        lines.push(
            `  ${code.qualname} · ${code.filename}:${code.firstlineno} · args ${code.argcount} · stack ${code.stacksize} · flags ${code.flagsText === '' ? '0' : code.flagsText} · ${code.instructions.length} instr · ${code.consts.length} const(s)`,
        );
        for (const instruction of code.instructions) {
            const arg = instruction.arg === null ? '     ' : String(instruction.arg).padStart(5);
            const resolved = instruction.resolved === null || instruction.resolved === '' ? '' : ` (${instruction.resolved})`;
            const caches = instruction.caches === 0 ? '' : ` +${instruction.caches} cache`;
            lines.push(`    ${String(instruction.offset).padStart(6)} ${instruction.name.padEnd(32)}${arg}${resolved}${caches}`);
        }
    }
    return lines.join('\n');
}

function describeDiff(report: DiffReport): string {
    const header = `left ${report.leftSize} B · right ${report.rightSize} B · ${report.identical ? 'identical' : 'different'} · compared ${report.comparedBytes} B`;
    if (report.identical) {
        return header;
    }
    const lines = [header];
    if (report.firstDifference !== null) {
        lines.push(`  first difference at ${hex(report.firstDifference)}`);
    }
    lines.push(`  ${entriesHeader(report.differences.length, report.total, 'differing range(s)', report.truncated)}`);
    for (const range of report.differences) {
        lines.push(`  ${hex(range.offset)} + ${range.length} byte(s)`);
    }
    return lines.join('\n');
}

function describeSearch(report: SearchReport): string {
    const header = `${report.hits.length} of ${report.total} ${report.mode} hit(s)${report.truncated ? ' (truncated)' : ''}`;
    if (report.hits.length === 0) {
        return `${header}\n  no matches`;
    }
    const lines = [header];
    for (const hit of report.hits) {
        lines.push(`  ${hex(hit.offset).padStart(10)}  ${hit.preview}`);
    }
    return lines.join('\n');
}

function describeFind(report: FindReport): string {
    const header = `${report.hits.length} of ${report.total} match(es)${report.truncated ? ' (truncated)' : ''}`;
    if (report.hits.length === 0) {
        return `${header}\n  no matches`;
    }
    const lines = [header];
    for (const hit of report.hits) {
        lines.push(`  ${hex(hit.offset).padStart(10)} len=${String(hit.length).padStart(4)}  ${hit.preview}`);
    }
    return lines.join('\n');
}

function describeCarve(report: CarveReport): string {
    const header = `${report.regions.length} region(s) for marker ${report.marker} (${report.total} match(es))${report.truncated ? ' (truncated)' : ''}`;
    if (report.regions.length === 0) {
        return `${header}\n  no printable region reached the minimum length`;
    }
    const lines = [header];
    for (const region of report.regions) {
        lines.push(
            `  ${hex(region.regionOffset).padStart(10)} len=${String(region.regionLength).padStart(6)} marker@${hex(region.markerOffset)}  ${region.preview}`,
        );
    }
    if (report.outputDir !== null) {
        lines.push(`  wrote ${report.regions.length} region file(s) to ${report.outputDir}`);
    }
    return lines.join('\n');
}

function describeTauriAssets(report: TauriAssetsReport): string {
    const header = `${report.assets.length} asset(s) of ${report.total}${report.truncated ? ' (truncated)' : ''}`;
    if (report.assets.length === 0) {
        return `${header}\n  no interleaved Tauri asset table found`;
    }
    const lines = [header];
    for (const asset of report.assets) {
        lines.push(
            `  ${hex(asset.blobOffset).padStart(10)} comp=${String(asset.compressedLen).padStart(8)} raw=${String(asset.decompressedLen).padStart(8)}  ${asset.key}`,
        );
    }
    if (report.outputDir !== null) {
        lines.push(`  wrote ${report.assets.length} asset file(s) to ${report.outputDir}`);
    }
    return lines.join('\n');
}

cli.command('capabilities', 'cli.cmd.capabilities').actionCtx(async (_options, _args, ctx) => {
    const matrix = capabilities();
    ctx.emitResult(matrix, describeCapabilities(matrix));
    return 0;
});

cli.command('info', 'cli.cmd.info').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const info = ctf.info();
        ctx.emitResult(info, describeInfo(info));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('sections', 'cli.cmd.sections').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.sections();
        ctx.emitResult(report, describeSections(report.sections));
        return 0;
    } finally {
        ctf.close();
    }
});

cli
    .command('strings', 'cli.cmd.strings')
    .option('--min <len>', 'cli.opt.min')
    .option('--limit <count>', 'cli.opt.limit')
    .option('--skip <count>', 'cli.opt.skip')
    .option('--all', 'cli.opt.all')
    .option('--encoding <encoding>', 'cli.opt.encoding')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const minText = text(options, 'min');
        const min = minText === undefined ? 4 : parseNumber(minText);
        if (min === undefined || min < 1) {
            ctx.fail('open-ctf.cli.min', { message: '`--min <len>` must be a positive integer' });
            return 2;
        }
        const all = options['all'] === true;
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? 100 : parseNumber(limitText);
        if (!all && (limit === undefined || limit < 1)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const skipText = text(options, 'skip');
        const skip = skipText === undefined ? 0 : parseNumber(skipText);
        if (skip === undefined) {
            ctx.fail('open-ctf.cli.skip', { message: '`--skip <count>` must be a non-negative integer' });
            return 2;
        }
        const encodings = ['ascii', 'utf16le', 'both'] as const;
        const encodingText = text(options, 'encoding') ?? 'ascii';
        if (!(encodings as readonly string[]).includes(encodingText)) {
            ctx.fail('cli.err.encoding', { message: '`--encoding` must be ascii, utf16le or both' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.stringsEncoded({
                minLength: min,
                ...(all ? {} : { limit }),
                skip,
                all,
                encoding: encodingText as StringEncoding,
            });
            ctx.emitResult(report, describeStrings(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('hexdump', 'cli.cmd.hexdump')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--length <length>', 'cli.opt.length')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? 0 : parseNumber(offsetText);
        if (offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const lengthText = text(options, 'length');
        const length = lengthText === undefined ? 256 : parseNumber(lengthText);
        if (length === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--length <length>` must be a non-negative integer' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.hexdump(offset, length);
            ctx.emitResult(report, report.text.length > 0 ? report.text : 'no bytes in the requested range');
            return 0;
        } finally {
            ctf.close();
        }
    });

cli.command('rva', 'cli.cmd.rva').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    const addressText = options._?.[1];
    if (file === undefined || addressText === undefined) {
        ctx.fail('open-ctf.cli.rva-args', { message: 'a binary file and an RVA are required' });
        return 2;
    }
    const address = parseNumber(addressText);
    if (address === undefined) {
        ctx.fail('open-ctf.cli.rva', { message: 'the RVA must be a non-negative integer, decimal or 0x-prefixed' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.rva(address);
        ctx.emitResult(report, `RVA ${hex(report.rva)} -> file offset ${hex(report.offset)}`);
        return 0;
    } finally {
        ctf.close();
    }
});

cli
    .command('imports', 'cli.cmd.imports')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.imports(limit);
            ctx.emitResult(report, describeImports(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('exports', 'cli.cmd.exports')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.exports(limit);
            ctx.emitResult(report, describeExports(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('symbols', 'cli.cmd.symbols')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.symbols(limit);
            ctx.emitResult(report, describeSymbols(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('debug', 'cli.cmd.debug')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.debug(limit);
            ctx.emitResult(report, describeDebug(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli.command('version', 'cli.cmd.version').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.version();
        ctx.emitResult(report, describeVersion(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('resources', 'cli.cmd.resources').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.resources();
        ctx.emitResult(report, describeResources(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('mitigations', 'cli.cmd.mitigations').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.mitigations();
        ctx.emitResult(report, describeMitigations(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('exception', 'cli.cmd.exception').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.exception();
        ctx.emitResult(report, describeException(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('pe-delay-imports', 'cli.cmd.peDelayImports').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.delayImports();
        ctx.emitResult(report, describeDelayImports(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('pe-bound-imports', 'cli.cmd.peBoundImports').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.boundImports();
        ctx.emitResult(report, describeBoundImports(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('pe-rich-header', 'cli.cmd.peRichHeader').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.richHeader();
        ctx.emitResult(report, describeRichHeader(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('elf-symbols', 'cli.cmd.elfSymbols').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.staticSymbols();
        ctx.emitResult(report, describeStaticSymbols(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('relocations', 'cli.cmd.relocations').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.relocations();
        ctx.emitResult(report, describeRelocations(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('dynamic', 'cli.cmd.dynamic').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.dynamic();
        ctx.emitResult(report, describeDynamic(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('segments', 'cli.cmd.segments').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.segments();
        ctx.emitResult(report, describeSegments(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('notes', 'cli.cmd.notes').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.notes();
        ctx.emitResult(report, describeNotes(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('certificates', 'cli.cmd.certificates').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.certificates();
        ctx.emitResult(report, describeCertificates(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('tls', 'cli.cmd.tls').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.tls();
        ctx.emitResult(report, describeTls(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('code-signature', 'cli.cmd.code-signature').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.codeSignature();
        ctx.emitResult(report, describeCodeSignature(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('load-config', 'cli.cmd.load-config').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.loadConfig();
        ctx.emitResult(report, describeLoadConfig(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('macho', 'cli.cmd.macho').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.macho();
        ctx.emitResult(report, describeMachO(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('macho-exports', 'cli.cmd.machoExports').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.machoExports();
        ctx.emitResult(report, describeMachOExports(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('macho-encryption', 'cli.cmd.machoEncryption').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.machoEncryption();
        ctx.emitResult(report, describeMachOEncryption(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('macho-chained-fixups', 'cli.cmd.machoChainedFixups').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.machoChainedFixups();
        ctx.emitResult(report, describeMachOChainedFixups(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli.command('macho-bindings', 'cli.cmd.machoBindings').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.machoBindings();
        ctx.emitResult(report, describeMachOBindings(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli
    .command('macho-function-starts', 'cli.cmd.machoFunctionStarts')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.machoFunctionStarts(limit);
            ctx.emitResult(report, describeMachOFunctionStarts(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('macho-symbols', 'cli.cmd.machoSymbols')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.machoSymbols(limit);
            ctx.emitResult(report, describeMachOSymbols(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli.command('macho-slices', 'cli.cmd.machoSlices').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.machoSlices();
        ctx.emitResult(report, describeMachOSlices(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli
    .command('macho-extract', 'cli.cmd.machoExtract')
    .option('--index <n>', 'cli.opt.index')
    .option('--out <file>', 'cli.opt.extractOut')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const indexText = text(options, 'index');
        const index = indexText === undefined ? 0 : parseNumber(indexText);
        if (index === undefined) {
            ctx.fail('open-ctf.cli.index', { message: '`--index <n>` must be a non-negative integer' });
            return 2;
        }
        const output = text(options, 'out');
        if (output === undefined) {
            ctx.fail('open-ctf.cli.out-required', { message: '`--out <file>` is required' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.extractSlice(index, output);
            ctx.emitResult(report, describeMachOSliceExtraction(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('disasm', 'cli.cmd.disasm')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--count <count>', 'cli.opt.count')
    .option('--syntax <syntax>', 'cli.opt.syntax')
    .option('--format <format>', 'cli.opt.disasmFormat')
    .option('--code <qualname>', 'cli.opt.disasmCode')
    .option('--python <version>', 'cli.opt.disasmPython')
    .option('--code-limit <count>', 'cli.opt.disasmCodeLimit')
    .option('--instruction-limit <count>', 'cli.opt.disasmInstructionLimit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? 0 : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const countText = text(options, 'count');
        const count = countText === undefined ? undefined : parseNumber(countText);
        if (countText !== undefined && (count === undefined || count < 1)) {
            ctx.fail('open-ctf.cli.count', { message: '`--count <count>` must be a positive integer' });
            return 2;
        }
        const syntax = text(options, 'syntax') ?? 'intel';
        if (syntax !== 'intel' && syntax !== 'masm' && syntax !== 'nasm') {
            ctx.fail('open-ctf.cli.syntax', { message: '`--syntax` must be intel, masm or nasm' });
            return 2;
        }
        const format = text(options, 'format') ?? 'auto';
        if (format !== 'auto' && format !== 'x86' && format !== 'pyc') {
            ctx.fail('open-ctf.cli.format', { message: '`--format` must be auto, x86 or pyc' });
            return 2;
        }
        const codeLimitText = text(options, 'code-limit');
        const codeLimit = codeLimitText === undefined ? undefined : parseNumber(codeLimitText);
        if (codeLimitText !== undefined && codeLimit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--code-limit <count>` must be a non-negative integer' });
            return 2;
        }
        const instructionLimitText = text(options, 'instruction-limit');
        const instructionLimit = instructionLimitText === undefined ? undefined : parseNumber(instructionLimitText);
        if (instructionLimitText !== undefined && instructionLimit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--instruction-limit <count>` must be a non-negative integer' });
            return 2;
        }
        const code = text(options, 'code');
        const pythonText = text(options, 'python');
        const python = pythonText === undefined ? undefined : parseNumber(pythonText);
        if (pythonText !== undefined && (python === undefined || python < 1)) {
            ctx.fail('open-ctf.cli.python', { message: '`--python <version>` must be a positive integer such as 312' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.disasm({
                offset,
                ...(count === undefined ? {} : { count }),
                syntax,
                format: format as DisassemblyFormat,
                ...(code === undefined ? {} : { code }),
                ...(python === undefined ? {} : { python }),
                ...(codeLimit === undefined ? {} : { codeLimit }),
                ...(instructionLimit === undefined ? {} : { instructionLimit }),
            });
            if ('codes' in report) {
                ctx.emitResult(report, describePyc(report));
            } else {
                ctx.emitResult(report, describeDisassembly(report));
            }
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('entropy', 'cli.cmd.entropy')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.entropy();
            ctx.emitResult(report, describeEntropy(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli.command('overlay', 'cli.cmd.overlay').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.overlay();
        ctx.emitResult(report, describeOverlay(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli
    .command('inflate', 'cli.cmd.inflate')
    .option('--offset <offset>', 'cli.opt.inflateOffset')
    .option('--format <format>', 'cli.opt.inflateFormat')
    .option('--limit <bytes>', 'cli.opt.inflateLimit')
    .option('--out <file>', 'cli.opt.inflateOut')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? 0 : parseNumber(offsetText);
        if (offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const formatText = text(options, 'format') ?? 'auto';
        if (!['auto', 'zlib', 'gzip', 'raw'].includes(formatText)) {
            ctx.fail('open-ctf.cli.format', { message: '`--format` must be auto, zlib, gzip or raw' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limit === undefined && limitText !== undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <bytes>` must be a non-negative integer' });
            return 2;
        }
        const out = text(options, 'out');
        const inflateOptions: InflateOptions = {
            offset,
            format: formatText as InflateFormat,
            ...(limit === undefined ? {} : { limit }),
            ...(out === undefined ? {} : { output: out }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.inflate(inflateOptions);
            ctx.emitResult(report, describeInflate(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('unpack', 'cli.cmd.unpack')
    .option('--format <format>', 'cli.opt.unpackFormat')
    .option('--offset <offset>', 'cli.opt.unpackOffset')
    .option('--entries-limit <count>', 'cli.opt.unpackEntriesLimit')
    .option('--commands-limit <count>', 'cli.opt.unpackCommandsLimit')
    .option('--strings-limit <count>', 'cli.opt.unpackStringsLimit')
    .option('--extract-dir <dir>', 'cli.opt.unpackExtractDir')
    .option('--extract-limit <bytes>', 'cli.opt.unpackExtractLimit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const format = text(options, 'format') ?? 'auto';
        if (!['auto', '7z', 'asar', 'nsis', 'pyinstaller', 'pyz'].includes(format)) {
            ctx.fail('open-ctf.cli.format', { message: '`--format <format>` must be auto, 7z, asar, nsis, pyinstaller or pyz' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? undefined : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const entriesLimitText = text(options, 'entries-limit');
        const entriesLimit = entriesLimitText === undefined ? undefined : parseNumber(entriesLimitText);
        const commandsLimitText = text(options, 'commands-limit');
        const commandsLimit = commandsLimitText === undefined ? undefined : parseNumber(commandsLimitText);
        const stringsLimitText = text(options, 'strings-limit');
        const stringsLimit = stringsLimitText === undefined ? undefined : parseNumber(stringsLimitText);
        const extractLimitText = text(options, 'extract-limit');
        const extractLimit = extractLimitText === undefined ? undefined : parseNumber(extractLimitText);
        const extractDir = text(options, 'extract-dir');
        const unpackOptions: UnpackOptions = {
            format: format as UnpackFormat,
            ...(offset === undefined ? {} : { offset }),
            ...(entriesLimit === undefined ? {} : { entriesLimit }),
            ...(commandsLimit === undefined ? {} : { commandsLimit }),
            ...(stringsLimit === undefined ? {} : { stringsLimit }),
            ...(extractDir === undefined ? {} : { extractDir }),
            ...(extractLimit === undefined ? {} : { extractLimit }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.unpack(unpackOptions);
            const described =
                report.format === '7z'
                    ? describeSevenZ(report)
                    : report.format === 'asar'
                      ? describeAsar(report)
                      : report.format === 'nsis'
                        ? describeNsis(report)
                        : describePyInstaller(report);
            ctx.emitResult(report, described);
            return 0;
        } finally {
            ctf.close();
        }
    });

function describeProbe(report: ProbeReport): string {
    const header = `${report.findings.length} candidate(s) in ${report.scanned} of ${report.size} byte(s)${report.truncated ? ' (truncated)' : ''}`;
    if (report.findings.length === 0) {
        return `${header}\n  no known magic matched`;
    }
    const lines = [header];
    for (const finding of report.findings) {
        lines.push(
            `  ${hex(finding.offset).padStart(10)} ${finding.format.padEnd(10)} ${finding.confidence.padEnd(9)} ${finding.reason}`,
        );
    }
    return lines.join('\n');
}

function describeHash(report: HashReport): string {
    const scope =
        report.offset === null
            ? `whole file (${report.length} byte(s))`
            : `range ${hex(report.offset)} +${report.length} byte(s)`;
    return `${report.algorithm} · ${scope}\n  ${report.digest}`;
}

function describeDecode(report: DecodeReport): string {
    const chain =
        report.steps.length === 0
            ? 'no decoder applied'
            : report.steps.map((step) => `${step.codec} ${step.inputLength}->${step.outputLength}`).join(' -> ');
    const body = report.text.length > 0 ? report.text : report.hex;
    return `${report.bytes} byte(s) · ${chain}${report.truncated ? ' (preview truncated)' : ''}\n${body}`;
}

function describeXor(report: XorReport): string {
    if (report.key !== null) {
        return `key 0x${report.key.toString(16).padStart(2, '0')} · ${report.length} byte(s)\n${report.plaintext ?? ''}`;
    }
    const lines = [`${report.length} byte(s); top ${report.guesses.length} key(s)`];
    for (const guess of report.guesses) {
        lines.push(`  0x${guess.keyHex} score=${guess.score.toFixed(3)}  ${guess.preview}`);
    }
    return lines.join('\n');
}

function describeGadgets(report: GadgetsReport): string {
    const header = `${report.hits.length} gadget(s) in ${report.scanned} byte(s)${report.truncated ? ' (truncated)' : ''}`;
    if (report.hits.length === 0) {
        return `${header}\n  no basic gadget matched`;
    }
    const lines = [header];
    for (const hit of report.hits) {
        const va = hit.va === null ? '' : `va=${hex(hit.va)}`;
        lines.push(
            `  ${hex(hit.offset).padStart(10)} ${va.padEnd(16)} ${hit.kind.padEnd(9)} ${hit.text}  [${hit.bytes}]`,
        );
    }
    return lines.join('\n');
}

function describeJwt(report: JwtReport): string {
    const lines = [
        `alg: ${report.algorithm.length > 0 ? report.algorithm : '(none)'}${report.unsigned ? ' · unsigned' : ''}`,
        `header: ${JSON.stringify(report.header)}`,
        `payload: ${JSON.stringify(report.payload)}`,
        `signature: ${report.signatureHex.length > 0 ? `${report.signatureHex.length / 2} byte(s)` : 'absent'}`,
    ];
    for (const warning of report.warnings) {
        lines.push(`warning: ${warning}`);
    }
    return lines.join('\n');
}

cli
    .command('probe', 'cli.cmd.probe')
    .option('--limit <count>', 'cli.opt.limit')
    .option('--scan-limit <bytes>', 'cli.opt.scanLimit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && limit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const scanLimitText = text(options, 'scan-limit');
        const scanLimit = scanLimitText === undefined ? undefined : parseNumber(scanLimitText);
        if (scanLimitText !== undefined && scanLimit === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--scan-limit <bytes>` must be a non-negative integer' });
            return 2;
        }
        const probeOptions: ProbeOptions = {
            ...(limit === undefined ? {} : { limit }),
            ...(scanLimit === undefined ? {} : { scanLimit }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.probe(probeOptions);
            ctx.emitResult(report, describeProbe(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('hash', 'cli.cmd.hash')
    .option('--alg <algorithm>', 'cli.opt.alg')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--length <length>', 'cli.opt.length')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const algorithms = ['md5', 'md4', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'];
        const algorithmText = text(options, 'alg') ?? 'sha256';
        if (!algorithms.includes(algorithmText)) {
            ctx.fail('cli.err.alg', { message: '`--alg` must be md5, md4, sha1, sha224, sha256, sha384 or sha512' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? undefined : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const lengthText = text(options, 'length');
        const length = lengthText === undefined ? undefined : parseNumber(lengthText);
        if (lengthText !== undefined && length === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--length <length>` must be a non-negative integer' });
            return 2;
        }
        const hashOptions: HashOptions = {
            algorithm: algorithmText as HashOptions['algorithm'],
            ...(offset === undefined ? {} : { offset }),
            ...(length === undefined ? {} : { length }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.hash(hashOptions);
            ctx.emitResult(report, describeHash(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('decode', 'cli.cmd.decode')
    .option('--codec <codec>', 'cli.opt.codec')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--length <length>', 'cli.opt.length')
    .option('--depth <count>', 'cli.opt.depth')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const codecs = ['auto', 'base64', 'base64url', 'hex', 'base32', 'rot13', 'percent', 'html'];
        const codecText = text(options, 'codec') ?? 'auto';
        if (!codecs.includes(codecText)) {
            ctx.fail('cli.err.codec', {
                message: '`--codec` must be auto, base64, base64url, hex, base32, rot13, percent or html',
            });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? undefined : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const lengthText = text(options, 'length');
        const length = lengthText === undefined ? undefined : parseNumber(lengthText);
        if (lengthText !== undefined && length === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--length <length>` must be a non-negative integer' });
            return 2;
        }
        const depthText = text(options, 'depth');
        const depth = depthText === undefined ? undefined : parseNumber(depthText);
        if (depthText !== undefined && depth === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--depth <count>` must be a positive integer' });
            return 2;
        }
        const decodeOptions: DecodeOptions = {
            codec: codecText as DecodeOptions['codec'],
            ...(offset === undefined ? {} : { offset }),
            ...(length === undefined ? {} : { length }),
            ...(depth === undefined ? {} : { depth }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.decode(decodeOptions);
            ctx.emitResult(report, describeDecode(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('xor', 'cli.cmd.xor')
    .option('--key <key>', 'cli.opt.xorKey')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--length <length>', 'cli.opt.length')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? undefined : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const lengthText = text(options, 'length');
        const length = lengthText === undefined ? undefined : parseNumber(lengthText);
        if (lengthText !== undefined && length === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--length <length>` must be a non-negative integer' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && limit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const key = text(options, 'key');
        const xorOptions: XorOptions = {
            ...(offset === undefined ? {} : { offset }),
            ...(length === undefined ? {} : { length }),
            ...(key === undefined ? {} : { key }),
            ...(limit === undefined ? {} : { limit }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.xor(xorOptions);
            ctx.emitResult(report, describeXor(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('gadgets', 'cli.cmd.gadgets')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--length <length>', 'cli.opt.length')
    .option('--all-sections', 'cli.opt.gadgetAllSections')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? undefined : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const lengthText = text(options, 'length');
        const length = lengthText === undefined ? undefined : parseNumber(lengthText);
        if (lengthText !== undefined && length === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--length <length>` must be a non-negative integer' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && limit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const gadgetOptions: GadgetOptions = {
            ...(offset === undefined ? {} : { offset }),
            ...(length === undefined ? {} : { length }),
            executableOnly: options['all-sections'] !== true,
            ...(limit === undefined ? {} : { limit }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.gadgets(gadgetOptions);
            ctx.emitResult(report, describeGadgets(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli.command('jwt', 'cli.cmd.jwt').actionCtx(async (options, _args, ctx) => {
    const token = input(options);
    if (token === undefined) {
        ctx.fail('open-ctf.cli.token-required', { message: 'a JWT is required' });
        return 2;
    }
    const report = decodeJwt(token);
    ctx.emitResult(report, describeJwt(report));
    return 0;
});

function describeUrl(report: UrlReport): string {
    const scheme = report.scheme === null ? '' : `${report.scheme}:`;
    const credentials = report.username === null ? '' : `${report.username}${report.password === null ? '' : ':<hidden>'}@`;
    const authority =
        report.host === null ? '' : `//${credentials}${report.host}${report.port === null ? '' : `:${report.port}`}`;
    const path = report.host !== null && report.path.length > 0 ? `/${report.path}` : report.path;
    const lines = [`${scheme}${authority}${path}`];
    if (report.query !== null) {
        lines.push(`query: ${report.query}`);
    }
    for (const param of report.params) {
        lines.push(`  ${param.decodedName} = ${param.decodedValue}`);
    }
    if (report.fragment !== null) {
        lines.push(`fragment: ${report.fragment}`);
    }
    if (report.decoded.length > 0 && report.decoded !== report.query) {
        lines.push(`decoded: ${report.decoded}`);
    }
    for (const warning of report.warnings) {
        lines.push(`warning: ${warning}`);
    }
    return lines.join('\n');
}

function describeCyclic(report: CyclicReport): string {
    const found = report.offset === null ? 'not found' : `offset ${report.offset}`;
    const pattern = report.pattern.length > 512 ? `${report.pattern.slice(0, 512)}...` : report.pattern;
    return `de Bruijn order ${report.order} · ${report.length} byte(s) · ${found}\n${pattern}`;
}

function describePacker(report: PackerReport): string {
    if (!report.packed) {
        return ['packed: no known signature', ...report.hints].join('\n');
    }
    const lines = [`packed: ${report.matches.length} signature(s)`];
    for (const match of report.matches) {
        const offset = match.offset === null ? '' : ` @ ${hex(match.offset)}`;
        lines.push(`  ${match.packer.padEnd(10)} ${match.confidence.padEnd(10)} ${match.evidence}${offset}`);
    }
    lines.push(...report.hints);
    return lines.join('\n');
}

function describeCaesar(report: CaesarReport): string {
    if (report.shift !== null) {
        return `shift ${report.shift} · ${report.length} byte(s)\n${report.plaintext ?? ''}`;
    }
    const lines = [`${report.length} byte(s); top ${report.candidates.length} shift(s)`];
    for (const candidate of report.candidates) {
        lines.push(`  ${String(candidate.shift).padStart(2)} score=${candidate.score.toFixed(3)}  ${candidate.preview}`);
    }
    return lines.join('\n');
}

function describePng(report: PngReport): string {
    const dimensions = report.width === null ? 'unknown size' : `${report.width}x${report.height}`;
    const flags = `${report.complete ? '' : ' · incomplete'}${report.truncated ? ' · listing truncated' : ''}`;
    const lines = [`PNG ${dimensions} · ${report.chunkCount} chunk(s)${flags}`];
    for (const chunk of report.chunks) {
        const text = chunk.keyword === null ? '' : ` ${chunk.keyword}=${chunk.text ?? ''}`;
        lines.push(`  ${hex(chunk.offset).padStart(10)} ${chunk.kind} ${String(chunk.length).padStart(8)}${text}`);
    }
    if (report.trailingBytes > 0) {
        lines.push(`trailing: ${report.trailingBytes} byte(s) at ${hex(report.trailingOffset ?? 0)}`);
    }
    return lines.join('\n');
}

function describePcap(report: PcapReport): string {
    const flags = `${report.truncated ? ' · truncated' : ''}`;
    const lines = [
        `pcap ${report.endianness}-endian ${report.timestampResolution} · ${report.packetCount} packet(s) · ${report.linkName} (${report.linkType})${flags}`,
    ];
    if (report.firstTimestamp !== null) {
        lines.push(`time: ${report.firstTimestamp.toFixed(6)} .. ${(report.lastTimestamp ?? report.firstTimestamp).toFixed(6)}`);
    }
    if (report.protocols.length > 0) {
        lines.push(`protocols: ${report.protocols.map((entry) => `${entry.name}=${entry.packets}`).join(', ')}`);
    }
    if (report.endpoints.length > 0) {
        lines.push(`endpoints: ${report.endpoints.map((entry) => `${entry.address}=${entry.packets}`).join(', ')}`);
    }
    return lines.join('\n');
}

cli.command('url', 'cli.cmd.url').actionCtx(async (options, _args, ctx) => {
    const value = input(options);
    if (value === undefined) {
        ctx.fail('open-ctf.cli.url-required', { message: 'a URL is required' });
        return 2;
    }
    const report = parseUrl(value);
    ctx.emitResult(report, describeUrl(report));
    return 0;
});

cli
    .command('cyclic', 'cli.cmd.cyclic')
    .option('--length <count>', 'cli.opt.length')
    .option('--find <value>', 'cli.opt.find')
    .actionCtx(async (options, _args, ctx) => {
        const lengthText = text(options, 'length');
        const length = lengthText === undefined ? undefined : parseNumber(lengthText);
        if (lengthText !== undefined && (length === undefined || length === 0)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--length <count>` must be a positive integer' });
            return 2;
        }
        const find = text(options, 'find');
        const cyclicOptions: CyclicOptions = {
            ...(length === undefined ? {} : { length }),
            ...(find === undefined ? {} : { find }),
        };
        const report = cyclic(cyclicOptions);
        ctx.emitResult(report, describeCyclic(report));
        return 0;
    });

cli.command('packer', 'cli.cmd.packer').actionCtx(async (options, _args, ctx) => {
    const file = input(options);
    if (file === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const report = ctf.packer({});
        ctx.emitResult(report, describePacker(report));
        return 0;
    } finally {
        ctf.close();
    }
});

cli
    .command('caesar', 'cli.cmd.caesar')
    .option('--shift <shift>', 'cli.opt.shift')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--length <length>', 'cli.opt.length')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const shiftText = text(options, 'shift');
        const shift = shiftText === undefined ? undefined : parseNumber(shiftText);
        if (shiftText !== undefined && (shift === undefined || shift > 25)) {
            ctx.fail('cli.err.shift', { message: '`--shift` must be an integer between 0 and 25' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? undefined : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const lengthText = text(options, 'length');
        const length = lengthText === undefined ? undefined : parseNumber(lengthText);
        if (lengthText !== undefined && length === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--length <length>` must be a non-negative integer' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && limit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const caesarOptions: CaesarOptions = {
            ...(offset === undefined ? {} : { offset }),
            ...(length === undefined ? {} : { length }),
            ...(shift === undefined ? {} : { shift }),
            ...(limit === undefined ? {} : { limit }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.caesar(caesarOptions);
            ctx.emitResult(report, describeCaesar(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('png', 'cli.cmd.png')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? undefined : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && limit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const pngOptions: PngOptions = {
            ...(offset === undefined ? {} : { offset }),
            ...(limit === undefined ? {} : { limit }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.png(pngOptions);
            ctx.emitResult(report, describePng(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('pcap', 'cli.cmd.pcap')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--limit <count>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? undefined : parseNumber(offsetText);
        if (offsetText !== undefined && offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && limit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const pcapOptions: PcapOptions = {
            ...(offset === undefined ? {} : { offset }),
            ...(limit === undefined ? {} : { limit }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.pcap(pcapOptions);
            ctx.emitResult(report, describePcap(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli.command('diff', 'cli.cmd.diff').actionCtx(async (options, _args, ctx) => {
    const leftPath = options._?.[0];
    const rightPath = options._?.[1];
    if (leftPath === undefined || rightPath === undefined) {
        ctx.fail('open-ctf.cli.file-required', { message: 'two binary files are required' });
        return 2;
    }
    const left = new OpenCTF({ path: leftPath });
    try {
        const right = new OpenCTF({ path: rightPath });
        try {
            const report = left.diff(right);
            ctx.emitResult(report, describeDiff(report));
            return 0;
        } finally {
            right.close();
        }
    } finally {
        left.close();
    }
});

cli
    .command('search', 'cli.cmd.search')
    .option('--mode <mode>', 'cli.opt.mode')
    .option('--case-sensitive', 'cli.opt.case')
    .option('--whole-word', 'cli.opt.word')
    .option('--limit <count>', 'cli.opt.limit')
    .option('--start <offset>', 'cli.opt.start')
    .option('--end <offset>', 'cli.opt.end')
    .actionCtx(async (options, _args, ctx) => {
        const file = options._?.[0];
        const pattern = options._?.[1];
        if (file === undefined || pattern === undefined) {
            ctx.fail('open-ctf.cli.search-args', { message: 'a binary file and a pattern are required' });
            return 2;
        }
        const modes = ['hex', 'ascii', 'utf16le'] as const;
        const modeText = text(options, 'mode') ?? 'ascii';
        if (!(modes as readonly string[]).includes(modeText)) {
            ctx.fail('open-ctf.cli.mode', { message: '`--mode` must be hex, ascii or utf16le' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const start = text(options, 'start') === undefined ? undefined : parseNumber(text(options, 'start'));
        if (text(options, 'start') !== undefined && start === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--start <offset>` must be a non-negative integer' });
            return 2;
        }
        const end = text(options, 'end') === undefined ? undefined : parseNumber(text(options, 'end'));
        if (text(options, 'end') !== undefined && end === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--end <offset>` must be a non-negative integer' });
            return 2;
        }
        const searchOptions: SearchOptions = {
            mode: modeText as SearchOptions['mode'],
            pattern,
            caseSensitive: options['case-sensitive'] === true,
            wholeWord: options['whole-word'] === true,
            ...(limit === undefined ? {} : { limit }),
            ...(start === undefined ? {} : { start }),
            ...(end === undefined ? {} : { end }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.search(searchOptions);
            ctx.emitResult(report, describeSearch(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('find', 'cli.cmd.find')
    .option('--pattern <regex>', 'cli.opt.pattern')
    .option('--skip <count>', 'cli.opt.skip')
    .option('--limit <count>', 'cli.opt.limit')
    .option('--context <bytes>', 'cli.opt.context')
    .option('--ignore-case', 'cli.opt.ignore-case')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const pattern = text(options, 'pattern');
        if (pattern === undefined || pattern.length === 0) {
            ctx.fail('cli.err.pattern', { message: '--pattern <regex> is required' });
            return 2;
        }
        const skipText = text(options, 'skip');
        const skip = skipText === undefined ? 0 : parseNumber(skipText);
        if (skip === undefined) {
            ctx.fail('open-ctf.cli.skip', { message: '`--skip <count>` must be a non-negative integer' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && (limit === undefined || limit < 1)) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a positive integer' });
            return 2;
        }
        const contextText = text(options, 'context');
        const context = contextText === undefined ? undefined : parseNumber(contextText);
        if (contextText !== undefined && context === undefined) {
            ctx.fail('open-ctf.cli.context', { message: '`--context <bytes>` must be a non-negative integer' });
            return 2;
        }
        const findOptions: FindOptions = {
            pattern,
            caseInsensitive: options['ignore-case'] === true,
            skip,
            ...(limit === undefined ? {} : { limit }),
            ...(context === undefined ? {} : { context }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.find(findOptions);
            ctx.emitResult(report, describeFind(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('dump', 'cli.cmd.dump')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--length <length>', 'cli.opt.length')
    .option('--output <path>', 'cli.opt.output')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = offsetText === undefined ? 0 : parseNumber(offsetText);
        if (offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const lengthText = text(options, 'length');
        const length = lengthText === undefined ? 256 : parseNumber(lengthText);
        if (length === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--length <length>` must be a non-negative integer' });
            return 2;
        }
        const output = text(options, 'output');
        if (output === undefined || output.length === 0) {
            ctx.fail('cli.err.outputRequired', { message: '--output <path> is required' });
            return 2;
        }
        const ctf = new OpenCTF({ path: file });
        try {
            const report: DumpReport = ctf.dump({ offset, length, output } satisfies DumpOptions);
            ctx.emitResult(report, `wrote ${report.written} byte(s) from ${hex(report.offset)} to ${report.output}`);
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('carve', 'cli.cmd.carve')
    .option('--marker <regex>', 'cli.opt.marker')
    .option('--min <size>', 'cli.opt.carveMin')
    .option('--max <size>', 'cli.opt.carveMax')
    .option('--expand-left <size>', 'cli.opt.expandLeft')
    .option('--limit <count>', 'cli.opt.limit')
    .option('--out <dir>', 'cli.opt.carveOut')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const marker = text(options, 'marker');
        if (marker === undefined || marker.length === 0) {
            ctx.fail('cli.err.markerRequired', { message: '--marker <regex> is required' });
            return 2;
        }
        const minText = text(options, 'min');
        const minRegion = minText === undefined ? undefined : parseNumber(minText);
        if (minText !== undefined && minRegion === undefined) {
            ctx.fail('open-ctf.cli.min', { message: '`--min <size>` must be a non-negative integer' });
            return 2;
        }
        const maxText = text(options, 'max');
        const maxRegion = maxText === undefined ? undefined : parseNumber(maxText);
        if (maxText !== undefined && maxRegion === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--max <size>` must be a non-negative integer' });
            return 2;
        }
        const expandText = text(options, 'expand-left');
        const expandLeft = expandText === undefined ? undefined : parseNumber(expandText);
        if (expandText !== undefined && expandLeft === undefined) {
            ctx.fail('open-ctf.cli.length', { message: '`--expand-left <size>` must be a non-negative integer' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && limit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a non-negative integer' });
            return 2;
        }
        const out = text(options, 'out');
        const carveOptions: CarveOptions = {
            marker,
            ...(minRegion === undefined ? {} : { minRegion }),
            ...(maxRegion === undefined ? {} : { maxRegion }),
            ...(expandLeft === undefined ? {} : { expandLeft }),
            ...(limit === undefined ? {} : { limit }),
            ...(out === undefined ? {} : { outputDir: out }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.carve(carveOptions);
            ctx.emitResult(report, describeCarve(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli
    .command('tauri-assets', 'cli.cmd.tauriAssets')
    .option('--out <dir>', 'cli.opt.tauriOut')
    .option('--limit <count>', 'cli.opt.tauriLimit')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const limitText = text(options, 'limit');
        const limit = limitText === undefined ? undefined : parseNumber(limitText);
        if (limitText !== undefined && limit === undefined) {
            ctx.fail('open-ctf.cli.limit', { message: '`--limit <count>` must be a non-negative integer' });
            return 2;
        }
        const out = text(options, 'out');
        const tauriOptions: TauriAssetsOptions = {
            ...(limit === undefined ? {} : { limit }),
            ...(out === undefined ? {} : { outputDir: out }),
        };
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.tauriAssets(tauriOptions);
            ctx.emitResult(report, describeTauriAssets(report));
            return 0;
        } finally {
            ctf.close();
        }
    });

cli.command('offset', 'cli.cmd.offset').actionCtx(async (options, _args, ctx) => {
    const file = options._?.[0];
    const offsetText = options._?.[1];
    if (file === undefined || offsetText === undefined) {
        ctx.fail('open-ctf.cli.offset-args', { message: 'a binary file and a file offset are required' });
        return 2;
    }
    const offset = parseNumber(offsetText);
    if (offset === undefined) {
        ctx.fail('open-ctf.cli.offset', { message: 'the offset must be a non-negative integer, decimal or 0x-prefixed' });
        return 2;
    }
    const ctf = new OpenCTF({ path: file });
    try {
        const mapped = ctf.offsetToVa(offset);
        let rva: number | null = null;
        try {
            rva = ctf.offsetToRva(offset).rva;
        } catch {
            rva = null;
        }
        const detail = rva === null ? `offset ${hex(offset)} -> VA ${hex(mapped.va)}` : `offset ${hex(offset)} -> RVA ${hex(rva)} · VA ${hex(mapped.va)}`;
        ctx.emitResult({ offset, rva, va: mapped.va }, detail);
        return 0;
    } finally {
        ctf.close();
    }
});

cli
    .command('patch', 'cli.cmd.patch')
    .option('--offset <offset>', 'cli.opt.offset')
    .option('--bytes <hex>', 'cli.opt.bytes')
    .option('--out <file>', 'cli.opt.out')
    .actionCtx(async (options, _args, ctx) => {
        const file = input(options);
        if (file === undefined) {
            ctx.fail('open-ctf.cli.file-required', { message: 'a binary file is required' });
            return 2;
        }
        const offsetText = text(options, 'offset');
        const offset = parseNumber(offsetText);
        if (offset === undefined) {
            ctx.fail('open-ctf.cli.offset', { message: '`--offset <offset>` must be a non-negative integer' });
            return 2;
        }
        const bytes = text(options, 'bytes');
        if (bytes === undefined || bytes.trim().length === 0) {
            ctx.fail('open-ctf.cli.bytes', { message: '`--bytes <hex>` is required, such as 90,90' });
            return 2;
        }
        const out = text(options, 'out');
        const ctf = new OpenCTF({ path: file });
        try {
            const report = ctf.patch(offset, bytes, out);
            ctx.emitResult(
                report,
                `patched ${report.path} at ${hex(report.offset)} (${report.length} byte(s))\n  before: ${report.beforeHash}\n  after:  ${report.afterHash}`,
            );
            return 0;
        } finally {
            ctf.close();
        }
    });

cli.command('gui', 'cli.cmd.gui').actionCtx(async (_options, _args, ctx) => {
    try {
        const status = await runGui({});
        ctx.emitResult(status, `window ${status.state}`);
        return 0;
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        ctx.fail('open-ctf.cli.gui-failed', { message });
        return 1;
    }
});

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
    const code = await cli.parse(process.argv);
    process.exitCode = code;
}
