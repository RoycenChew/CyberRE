# ADR-023: The Ghidra export script is Java

## Status
Accepted. Supersedes the Jython choice implied by ADR-004.

## Context
The exporter was written as a Jython script, which was the conventional
choice for Ghidra scripting and worked on 11.x. Installing Ghidra 12.1.2 to
exercise the real-tool tier showed the ground had moved:

* **Jython is not bundled.** Ghidra 12.1.2 ships it only as an optional
  extension under `Extensions/Ghidra/..._Jython.zip`. A script that requires
  an extension to be installed first is a script that silently does not run.
* **PyGhidra is bundled, but not in headless by default.** Running the
  ported PyGhidra script under `analyzeHeadless` fails with "Ghidra was not
  started with PyGhidra. Python is not available". Enabling it means
  launching through `pyghidraRun -H`, which needs Python 3 on PATH and
  JPype inside Ghidra's process, with a first-run install step.
* **Java needs nothing.** Ghidra compiles `.java` scripts in its own JVM.
  The installation ships 326 of them, and Gson 2.13.2 is on the classpath.

Each Python option adds a dependency chain between CyberRE and a successful
analysis, on the machine of whoever is running it. For an enterprise tool
where the Ghidra integration has to work on a customer's host and in CI
without a setup ritual, that is the wrong trade.

## Decision
`CyberREExport.java`, run as a headless post-script. No Jython extension, no
PyGhidra, no Python inside Ghidra, no JPype. Output shape unchanged;
`SCRIPT_VERSION` 3.0.0, since the script is not the same script and the
version exists to say so.

## Consequences
The integration now depends only on Ghidra and a JDK, both of which are
already required. Verified end to end against Ghidra 12.1.2: 278 functions,
86 imports, 223 strings and 897 call edges recovered from a real PE, parsed
into provenanced evidence.

The cost is that the exporter is Java, which is more verbose than Python and
a smaller pool of contributors will be comfortable editing. Against that, it
is one file of mechanical API calls behind an adapter, and it is the only
version of the script that runs on an unmodified Ghidra installation.

Two bugs surfaced during this work that recorded fixtures could never have
caught, which is the argument for the real-tool tier in one line:

* `analyzeHeadless` requires the project directory to exist already and
  aborts with "Directory not found" otherwise; the runner was passing a path
  it had not created.
* `DefinedDataIterator.definedStrings(Program)` does not exist in 12.1.2.
  String collection now iterates the listing and filters on value type,
  which is the API that has not moved between releases.
