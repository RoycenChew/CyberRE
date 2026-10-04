/* CyberRE Ghidra export script.
 *
 * Runs INSIDE Ghidra as a headless post-script, in Ghidra's own JVM. Java
 * rather than Python, deliberately (ADR-023): the Java GhidraScript
 * interface has been stable across every release and needs no runtime
 * beyond the one Ghidra is already running in.
 *
 * Jython is not bundled in Ghidra 12 - it ships only as an optional
 * extension - and PyGhidra headless requires launching through
 * pyghidraRun with Python 3 and JPype present inside Ghidra's process.
 * Both add a dependency chain between CyberRE and a successful analysis.
 * This script adds none.
 *
 * It writes one JSON document describing the binary and exits. Everything
 * interpretive - what an import means, whether a path is reachable,
 * whether any of it is a security problem - happens in CyberRE, over typed
 * evidence. This script reports facts.
 *
 * SCRIPT_VERSION is part of the analysis cache key and of the provenance of
 * every piece of evidence this produces. Bump it whenever the output
 * changes shape or content, or cached results from an older script will be
 * served as though they came from this one.
 *
 * @category CyberRE
 */

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

public class CyberREExport extends GhidraScript {

    private static final int SCHEMA_VERSION = 1;

    /*
     * 3.0.0: ported to Java. 1.0.0 was Jython, 2.0.0 PyGhidra. The document
     * shape is unchanged across all three, but the script is not the same
     * script, and the version exists precisely to say so - a cached export
     * from an older one must not be served as though it came from this.
     */
    private static final String SCRIPT_VERSION = "3.0.0";

    /* A string shorter than this is mostly noise in a compiled binary. */
    private static final int MIN_STRING_LENGTH = 4;

    /*
     * Ceilings, so a pathological binary produces a large export rather than
     * an unbounded one. Truncation is reported in the document: a silently
     * shortened list would look like an absence of findings.
     */
    private static final int MAX_STRINGS = 20000;
    private static final int MAX_FUNCTIONS = 50000;
    private static final int MAX_CALL_EDGES = 200000;

    private boolean stringsTruncated = false;
    private boolean functionsTruncated = false;
    private boolean callEdgesTruncated = false;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("CyberREExport: an output path argument is required");
            throw new IllegalArgumentException("missing output path");
        }

        JsonObject document = new JsonObject();
        document.addProperty("schema_version", SCHEMA_VERSION);
        document.addProperty("script_version", SCRIPT_VERSION);
        document.addProperty("ghidra_version", ghidraVersion());
        document.addProperty("program_name", currentProgram.getName());
        document.add("binary", collectMetadata());
        document.add("sections", collectSections());
        document.add("imports", collectImports());
        document.add("exports", collectExports());
        document.add("strings", collectStrings());
        document.add("functions", collectFunctions());
        document.add("call_edges", collectCallEdges());

        JsonObject truncated = new JsonObject();
        truncated.addProperty("strings", stringsTruncated);
        truncated.addProperty("functions", functionsTruncated);
        truncated.addProperty("call_edges", callEdgesTruncated);
        document.add("truncated", truncated);
        document.addProperty("cancelled", monitor.isCancelled());

        write(args[0], document);
        println("CyberREExport: wrote " + args[0]);
    }

    private void write(String path, JsonObject document) throws IOException {
        try (Writer writer =
                Files.newBufferedWriter(Paths.get(path), StandardCharsets.UTF_8)) {
            new Gson().toJson(document, writer);
        }
    }

    /*
     * The running Ghidra version. It goes into the cache key and into the
     * provenance of every piece of evidence from this run, so it is read
     * rather than assumed.
     */
    private String ghidraVersion() {
        try {
            return Application.getApplicationVersion();
        }
        catch (Exception e) {
            return "unknown";
        }
    }

    private static Long offsetOf(Address address) {
        return address == null ? null : Long.valueOf(address.getOffset());
    }

    private static void addAddress(JsonObject object, String key, Address address) {
        Long offset = offsetOf(address);
        if (offset == null) {
            object.add(key, JsonNull.INSTANCE);
        }
        else {
            object.addProperty(key, offset);
        }
    }

    private JsonObject collectMetadata() {
        Language language = currentProgram.getLanguage();

        Long entry = null;
        for (Address address : currentProgram.getSymbolTable().getExternalEntryPointIterator()) {
            entry = offsetOf(address);
            break;
        }

        JsonObject binary = new JsonObject();
        binary.addProperty("format", currentProgram.getExecutableFormat());
        binary.addProperty("architecture", language.getProcessor().toString());
        binary.addProperty("bits", language.getLanguageDescription().getSize());
        binary.addProperty("endianness", language.isBigEndian() ? "big" : "little");
        if (entry == null) {
            binary.add("entry_point", JsonNull.INSTANCE);
        }
        else {
            binary.addProperty("entry_point", entry);
        }
        binary.addProperty("compiler",
            currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        addAddress(binary, "image_base", currentProgram.getImageBase());
        String sha256 = currentProgram.getExecutableSHA256();
        binary.addProperty("sha256", sha256 == null ? "" : sha256);
        return binary;
    }

    private JsonArray collectSections() {
        JsonArray sections = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            JsonObject section = new JsonObject();
            section.addProperty("name", block.getName());
            addAddress(section, "start", block.getStart());
            section.addProperty("virtual_size", block.getSize());
            section.addProperty("raw_size", block.getSize());
            section.addProperty("executable", block.isExecute());
            section.addProperty("writable", block.isWrite());
            section.addProperty("readable", block.isRead());
            section.addProperty("initialized", block.isInitialized());
            sections.add(section);
        }
        return sections;
    }

    private JsonArray collectImports() {
        JsonArray imports = new JsonArray();
        for (Symbol symbol : currentProgram.getSymbolTable().getExternalSymbols()) {
            JsonObject entry = new JsonObject();
            Namespace parent = symbol.getParentNamespace();
            if (parent == null) {
                entry.add("library", JsonNull.INSTANCE);
            }
            else {
                entry.addProperty("library", parent.getName());
            }
            entry.addProperty("symbol", symbol.getName());
            addAddress(entry, "address", symbol.getAddress());
            imports.add(entry);
        }
        return imports;
    }

    private JsonArray collectExports() {
        JsonArray exports = new JsonArray();
        for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
            if (!symbol.isExternalEntryPoint()) {
                continue;
            }
            JsonObject entry = new JsonObject();
            entry.addProperty("symbol", symbol.getName());
            addAddress(entry, "address", symbol.getAddress());
            exports.add(entry);
        }
        return exports;
    }

    private JsonArray collectStrings() {
        JsonArray strings = new JsonArray();
        /*
         * Iterating defined data and filtering on the value type, rather
         * than using a string-specific helper: the helper's signature has
         * moved between Ghidra releases, and the listing API has not.
         */
        DataIterator defined = currentProgram.getListing().getDefinedData(true);
        while (defined.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            if (strings.size() >= MAX_STRINGS) {
                stringsTruncated = true;
                break;
            }
            Data data = defined.next();
            Object value = data.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            String text = (String) value;
            if (text.length() < MIN_STRING_LENGTH) {
                continue;
            }
            JsonObject entry = new JsonObject();
            entry.addProperty("value", text);
            addAddress(entry, "address", data.getAddress());
            DataType type = data.getDataType();
            boolean unicode =
                type != null && type.getName().toLowerCase().contains("unicode");
            entry.addProperty("encoding", unicode ? "utf-16" : "ascii");
            strings.add(entry);
        }
        return strings;
    }

    private JsonArray collectFunctions() {
        JsonArray functions = new JsonArray();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) {
                break;
            }
            if (functions.size() >= MAX_FUNCTIONS) {
                functionsTruncated = true;
                break;
            }
            JsonObject entry = new JsonObject();
            entry.addProperty("name", function.getName());
            addAddress(entry, "address", function.getEntryPoint());
            entry.addProperty("size", function.getBody().getNumAddresses());
            entry.addProperty("is_thunk", function.isThunk());
            entry.addProperty("is_external", function.isExternal());
            entry.addProperty("calling_convention", function.getCallingConventionName());
            entry.addProperty("parameter_count", function.getParameterCount());
            functions.add(entry);
        }
        return functions;
    }

    private JsonArray collectCallEdges() {
        JsonArray edges = new JsonArray();
        outer:
        for (Function caller : currentProgram.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) {
                break;
            }
            for (Function callee : caller.getCalledFunctions(monitor)) {
                if (edges.size() >= MAX_CALL_EDGES) {
                    callEdgesTruncated = true;
                    break outer;
                }
                JsonObject edge = new JsonObject();
                edge.addProperty("caller", caller.getName());
                edge.addProperty("callee", callee.getName());
                addAddress(edge, "call_site", caller.getEntryPoint());
                edges.add(edge);
            }
        }
        return edges;
    }
}
