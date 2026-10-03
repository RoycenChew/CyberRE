## CyberRE Ghidra export script.
##
## Runs INSIDE Ghidra under Jython 2.7 as a headless post-script. It is not
## importable by CyberRE and is not type-checked or linted with the rest of
## the codebase - hence Python 2 compatible syntax, no f-strings, and no
## imports from `cyberre`.
##
## It writes one JSON document describing the binary and exits. Everything
## interpretive - what an import means, whether a path is reachable, whether
## any of it is a security problem - happens in CyberRE, over typed evidence.
## This script reports facts.
##
## SCRIPT_VERSION is part of the analysis cache key and of every piece of
## evidence this produces. Bump it whenever the output changes shape or
## content, or cached results from an older script will be served as though
## they came from the new one.
##
## @category CyberRE
## @runtime Jython

import json
import sys

SCHEMA_VERSION = 1
SCRIPT_VERSION = "1.0.0"

# A string shorter than this is mostly noise in a compiled binary.
MIN_STRING_LENGTH = 4

# Ceilings, so a pathological binary produces a large export rather than an
# unbounded one. Truncation is reported in the document: a silently shortened
# list would look like an absence of findings.
MAX_STRINGS = 20000
MAX_FUNCTIONS = 50000
MAX_CALL_EDGES = 200000


def _address_of(address):
    try:
        return int(address.getOffset())
    except Exception:
        return None


def collect_metadata(program):
    language = program.getLanguage()
    processor = language.getProcessor().toString()
    compiler_spec = program.getCompilerSpec().getCompilerSpecID().getIdAsString()
    entry = None
    symbol_table = program.getSymbolTable()
    for symbol in symbol_table.getExternalEntryPointIterator():
        entry = _address_of(symbol)
        break

    return {
        "format": program.getExecutableFormat(),
        "architecture": processor,
        "bits": language.getLanguageDescription().getSize(),
        "endianness": "big" if language.isBigEndian() else "little",
        "entry_point": entry,
        "compiler": compiler_spec,
        "image_base": _address_of(program.getImageBase()),
        "sha256": program.getExecutableSHA256(),
    }


def collect_sections(program):
    sections = []
    for block in program.getMemory().getBlocks():
        sections.append(
            {
                "name": block.getName(),
                "start": _address_of(block.getStart()),
                "virtual_size": int(block.getSize()),
                "raw_size": int(block.getSize()),
                "executable": bool(block.isExecute()),
                "writable": bool(block.isWrite()),
                "readable": bool(block.isRead()),
                "initialized": bool(block.isInitialized()),
            }
        )
    return sections


def collect_imports(program):
    imports = []
    symbol_table = program.getSymbolTable()
    for library in symbol_table.getExternalSymbols():
        parent = library.getParentNamespace()
        imports.append(
            {
                "library": parent.getName() if parent is not None else None,
                "symbol": library.getName(),
                "address": _address_of(library.getAddress()),
            }
        )
    return imports


def collect_exports(program):
    exports = []
    symbol_table = program.getSymbolTable()
    for symbol in symbol_table.getAllSymbols(True):
        if symbol.isExternalEntryPoint():
            exports.append(
                {"symbol": symbol.getName(), "address": _address_of(symbol.getAddress())}
            )
    return exports


def collect_strings(program, monitor):
    from ghidra.program.util import DefinedDataIterator

    strings = []
    truncated = False
    for data in DefinedDataIterator.definedStrings(program):
        if monitor.isCancelled():
            break
        if len(strings) >= MAX_STRINGS:
            truncated = True
            break
        value = data.getValue()
        if value is None:
            continue
        text = str(value)
        if len(text) < MIN_STRING_LENGTH:
            continue
        strings.append(
            {
                "value": text,
                "address": _address_of(data.getAddress()),
                "encoding": "utf-16" if "unicode" in str(data.getDataType()).lower() else "ascii",
            }
        )
    return strings, truncated


def collect_functions(program, monitor):
    functions = []
    truncated = False
    for function in program.getFunctionManager().getFunctions(True):
        if monitor.isCancelled():
            break
        if len(functions) >= MAX_FUNCTIONS:
            truncated = True
            break
        functions.append(
            {
                "name": function.getName(),
                "address": _address_of(function.getEntryPoint()),
                "size": int(function.getBody().getNumAddresses()),
                "is_thunk": bool(function.isThunk()),
                "is_external": bool(function.isExternal()),
                "calling_convention": str(function.getCallingConventionName()),
                "parameter_count": int(function.getParameterCount()),
            }
        )
    return functions, truncated


def collect_call_edges(program, monitor):
    edges = []
    truncated = False
    manager = program.getFunctionManager()
    for function in manager.getFunctions(True):
        if monitor.isCancelled():
            break
        caller = function.getName()
        for callee in function.getCalledFunctions(monitor):
            if len(edges) >= MAX_CALL_EDGES:
                truncated = True
                break
            edges.append(
                {
                    "caller": caller,
                    "callee": callee.getName(),
                    "call_site": _address_of(function.getEntryPoint()),
                }
            )
        if truncated:
            break
    return edges, truncated


def main():
    program = currentProgram  # noqa: F821 - injected by Ghidra
    monitor = getMonitor()  # noqa: F821 - injected by Ghidra
    args = getScriptArgs()  # noqa: F821 - injected by Ghidra

    if not args:
        print("cyberre_export: an output path argument is required")
        sys.exit(2)
    output_path = args[0]

    strings, strings_truncated = collect_strings(program, monitor)
    functions, functions_truncated = collect_functions(program, monitor)
    call_edges, edges_truncated = collect_call_edges(program, monitor)

    document = {
        "schema_version": SCHEMA_VERSION,
        "script_version": SCRIPT_VERSION,
        "ghidra_version": str(getGhidraVersion()),  # noqa: F821
        "program_name": program.getName(),
        "binary": collect_metadata(program),
        "sections": collect_sections(program),
        "imports": collect_imports(program),
        "exports": collect_exports(program),
        "strings": strings,
        "functions": functions,
        "call_edges": call_edges,
        # Reported, never inferred from a short list. An analysis that was
        # cut short must say so, or partial coverage reads as a clean result.
        "truncated": {
            "strings": strings_truncated,
            "functions": functions_truncated,
            "call_edges": edges_truncated,
        },
        "cancelled": bool(monitor.isCancelled()),
    }

    handle = open(output_path, "w")
    try:
        json.dump(document, handle)
    finally:
        handle.close()
    print("cyberre_export: wrote " + output_path)


main()
