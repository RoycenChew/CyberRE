"""Taint and reachability analysis for Python source.

Built on `ast` from the standard library. Python's own parser is the right
tool for parsing Python, and this needs no dependency.

**What this is.** A deliberately simple analyser: it tracks tainted values
within a function, propagates taint one level into called functions, and
recognises a fixed set of sources, sinks and sanitisers. It answers the
three questions a taint requirement asks - does attacker-influenced data
reach a dangerous operation, is anything sanitising it, and is the code
reachable from an entry point.

**What this is not.** It is not a sound static analyser. It does not model
aliasing, containers, attributes, class state, decorators that rewrite
behaviour, or dynamic dispatch. It will miss real flows, and it will
occasionally see one that a human would not.

That is why its evidence carries a middling reliability and why the
requirement sets demand corroboration: this capability narrows an
investigation, it does not settle one. Overstating its strength would be
the failure mode that matters, since a confident wrong answer costs more
than a cautious silent one.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

TOOL_NAME = "pytaint"
ANALYSER_VERSION = "1.0.0"

#: Expressions that introduce attacker-influenced data. Matched on the
#: dotted tail, so `flask.request.args.get` and `request.args.get` both hit.
SOURCES: dict[str, str] = {
    "request.args.get": "HTTP query parameter",
    "request.args": "HTTP query parameters",
    "request.form.get": "HTTP form field",
    "request.form": "HTTP form data",
    "request.json": "HTTP JSON body",
    "request.data": "HTTP request body",
    "request.values.get": "HTTP request value",
    "request.cookies.get": "HTTP cookie",
    "request.headers.get": "HTTP header",
    "request.GET.get": "HTTP query parameter",
    "request.POST.get": "HTTP form field",
    "request.body": "HTTP request body",
    "input": "interactive input",
    "sys.argv": "command-line argument",
    "os.environ.get": "environment variable",
    "os.getenv": "environment variable",
}

#: The distinct descriptions in SOURCES, as a set. A flow whose source is
#: one of these began outside the trust boundary; anything else - most
#: importantly an unresolved "parameter 'x'" - did not.
SOURCE_DESCRIPTIONS: frozenset[str] = frozenset(SOURCES.values())

#: Dangerous operations, and the weakness class each belongs to. The class
#: matters because it decides which requirement set the resulting evidence
#: can contribute to.
SINKS: dict[str, str] = {
    "subprocess.call": "command",
    "subprocess.run": "command",
    "subprocess.Popen": "command",
    "subprocess.check_output": "command",
    "subprocess.check_call": "command",
    "os.system": "command",
    "os.popen": "command",
    "os.execv": "command",
    "commands.getoutput": "command",
    "eval": "code",
    "exec": "code",
    "compile": "code",
    "cursor.execute": "sql",
    "cursor.executemany": "sql",
    "connection.execute": "sql",
    "session.execute": "sql",
    "db.execute": "sql",
    "pickle.loads": "deserialise",
    "pickle.load": "deserialise",
    "yaml.load": "deserialise",
    "marshal.loads": "deserialise",
    "open": "path",
    "os.remove": "path",
    "os.unlink": "path",
    "shutil.rmtree": "path",
    "send_file": "path",
}

#: Calls that render a tainted value safe for some sink. Recorded by name,
#: because which sanitiser was used is what a reviewer needs in order to
#: judge whether it is the right one.
SANITISERS: dict[str, str] = {
    "shlex.quote": "shlex.quote",
    "shlex.split": "shlex.split",
    "int": "int()",
    "float": "float()",
    "bool": "bool()",
    "os.path.basename": "os.path.basename",
    "secure_filename": "secure_filename",
    "re.escape": "re.escape",
    "html.escape": "html.escape",
    "urllib.parse.quote": "urllib.parse.quote",
    "escape": "escape",
}

#: Decorators that mark a function as reachable from outside. A route
#: handler is an entry point whether or not anything in the file calls it,
#: which is exactly the case a naive call-graph walk gets wrong.
ENTRY_DECORATORS = (
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "websocket",
    "task",
    "command",
    "handler",
    "lambda_handler",
    "api_view",
)

#: Functions treated as entry points by name.
ENTRY_NAMES = frozenset({"main", "handler", "lambda_handler", "application"})

#: Cap on how far a flow is traced. A path longer than this is not a useful
#: explanation even when it is real.
MAX_DEPTH = 6


def dotted_name(node: ast.AST) -> str:
    """The dotted form of an attribute or name expression, or ``""``."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    elif isinstance(current, ast.Call):
        return dotted_name(current.func)
    else:
        return ""
    return ".".join(reversed(parts))


def _matches(name: str, table: dict[str, str]) -> str | None:
    """Match a dotted name against a table, tail-first.

    `a.b.request.args.get` should match `request.args.get`: the import
    style and the local alias vary, and the meaningful part is the tail.
    """
    if not name:
        return None
    if name in table:
        return table[name]
    parts = name.split(".")
    for start in range(1, len(parts)):
        candidate = ".".join(parts[start:])
        if candidate in table:
            return table[candidate]
    return None


@dataclass
class Flow:
    """One path from a source to a sink."""

    source: str
    sink: str
    sink_category: str
    steps: tuple[str, ...]
    sanitisers: tuple[str, ...]
    line: int
    function: str
    excerpt: str | None = None


@dataclass
class FunctionFacts:
    """What one function does, as far as this analyser can tell."""

    name: str
    qualified: str
    line: int
    calls: set[str] = field(default_factory=set)
    call_argument_sources: dict[str, tuple[tuple[str | None, tuple[str, ...]], ...]] = field(
        default_factory=dict
    )
    """For each function this one calls, what taints each positional
    argument and which sanitisers it passed through.

    The source is needed so propagation can carry the *caller's* origin
    into the helper: a flow beginning at "parameter 'host'" does not
    establish attacker influence.

    The sanitisers are needed for the opposite reason. A caller that
    writes `ping(shlex.quote(value))` has sanitised it, and a helper flow
    that records no sanitiser is a false positive - the exact kind this
    system exists to avoid.
    """
    is_entry: bool = False
    tainted_parameters: set[int] = field(default_factory=set)
    """Parameter positions that, if given tainted data, reach a sink.

    This is the whole of the interprocedural model: a helper that passes
    its argument to a sink taints its caller's argument. One level, which
    covers the common `route -> helper -> sink` shape without pretending
    to whole-program analysis.
    """


class _FunctionAnalyser(ast.NodeVisitor):
    """Tracks taint within a single function."""

    def __init__(self, function: ast.FunctionDef | ast.AsyncFunctionDef, module: str) -> None:
        self._function = function
        self._module = module
        self._tainted: dict[str, str] = {}
        """Variable name to the source description that tainted it."""

        self._sanitised: dict[str, list[str]] = {}
        """Variable name to sanitisers applied on the way."""

        self.flows: list[Flow] = []
        self.calls: set[str] = set()
        self.call_argument_sources: dict[str, tuple[tuple[str | None, tuple[str, ...]], ...]] = {}
        self.tainted_parameters: set[int] = set()
        self._parameters = [arg.arg for arg in function.args.args]

    # ------------------------------------------------------------ helpers

    def _taint_of(self, node: ast.AST) -> tuple[str | None, list[str]]:
        """What taints `node`, and which sanitisers it passed through."""
        if isinstance(node, ast.Name):
            if node.id in self._tainted:
                return self._tainted[node.id], list(self._sanitised.get(node.id, []))
            if node.id in self._parameters:
                # A parameter is potentially attacker-influenced. Treated
                # as a candidate rather than a fact: whether it really is
                # depends on the caller, which the caller-side pass checks.
                return f"parameter '{node.id}'", []
            return None, []

        if isinstance(node, ast.Call):
            name = dotted_name(node.func)
            source = _matches(name, SOURCES)
            if source is not None:
                return source, []

            sanitiser = _matches(name, SANITISERS)
            if sanitiser is not None:
                for argument in node.args:
                    inner, applied = self._taint_of(argument)
                    if inner is not None:
                        return inner, [*applied, sanitiser]
                return None, []

            for argument in node.args:
                inner, applied = self._taint_of(argument)
                if inner is not None:
                    return inner, applied
            return None, []

        if isinstance(node, ast.Attribute | ast.Subscript):
            source = _matches(dotted_name(node), SOURCES)
            if source is not None:
                return source, []
            if isinstance(node, ast.Subscript):
                return self._taint_of(node.value)
            return self._taint_of(node.value)

        if isinstance(node, ast.BinOp):
            for side in (node.left, node.right):
                inner, applied = self._taint_of(side)
                if inner is not None:
                    return inner, applied
            return None, []

        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    inner, applied = self._taint_of(value.value)
                    if inner is not None:
                        return inner, applied
            return None, []

        if isinstance(node, ast.List | ast.Tuple):
            for element in node.elts:
                inner, applied = self._taint_of(element)
                if inner is not None:
                    return inner, applied
            return None, []

        return None, []

    # ------------------------------------------------------------- visits

    def visit_Assign(self, node: ast.Assign) -> None:
        source, sanitisers = self._taint_of(node.value)
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if source is None:
                self._tainted.pop(target.id, None)
                self._sanitised.pop(target.id, None)
            else:
                self._tainted[target.id] = source
                self._sanitised[target.id] = sanitisers
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func)
        if name:
            short = name.split(".")[-1]
            self.calls.add(short)
            # What this call passes, so propagation can carry a real
            # source into the callee rather than a parameter name.
            self.call_argument_sources[short] = tuple(
                (lambda pair: (pair[0], tuple(pair[1])))(self._taint_of(argument))
                for argument in node.args
            )

        category = _matches(name, SINKS)
        if category is not None:
            self._check_sink(node, name, category)

        # A tainted value passed to a local helper: the caller-side pass
        # uses this to decide whether the helper's parameter is reachable
        # from a source.
        for argument in node.args:
            source, _ = self._taint_of(argument)
            if source is not None and source.startswith("parameter '"):
                index = self._parameter_index(source)
                if index is not None:
                    self.tainted_parameters.add(index)

        self.generic_visit(node)

    def _parameter_index(self, source: str) -> int | None:
        name = source.removeprefix("parameter '").rstrip("'")
        return self._parameters.index(name) if name in self._parameters else None

    @staticmethod
    def _shell_enabled(node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg == "shell":
                return isinstance(keyword.value, ast.Constant) and bool(keyword.value.value)
        return False

    @staticmethod
    def _how_reached(argument: ast.AST) -> str:
        """How the tainted value enters the call.

        The distinction that decides whether a command sink is
        exploitable: a value interpolated into a command string is
        attacker-controlled shell syntax, while the same value passed as
        its own argv element is just an argument. Without recording this
        the evidence cannot tell the two apart - which an adversarial
        review said in exactly those terms.
        """
        if isinstance(argument, ast.BinOp):
            return "string concatenation into the command"
        if isinstance(argument, ast.JoinedStr):
            return "f-string interpolation into the command"
        if isinstance(argument, ast.List | ast.Tuple):
            return "separate argument vector element"
        if isinstance(argument, ast.Call):
            name = dotted_name(argument.func)
            if name.endswith(".format") or name.endswith(".join"):
                return "string formatting into the command"
        return "passed directly"

    def _check_sink(self, node: ast.Call, name: str, category: str) -> None:
        """Record a flow if tainted data reaches this call."""
        if category == "sql" and len(node.args) >= 2:
            query_taint, _ = self._taint_of(node.args[0])
            if query_taint is None:
                # Parameterised: the statement is a literal and the values
                # are bound. The flow is still recorded, with the binding
                # named as the sanitiser, because a reviewer asking "is
                # this injectable?" needs to see that it was checked.
                for argument in node.args[1:]:
                    bound, _ = self._taint_of(argument)
                    if bound is not None:
                        self.flows.append(
                            Flow(
                                source=bound,
                                sink=name,
                                sink_category=category,
                                steps=(),
                                sanitisers=("parameterised query",),
                                line=node.lineno,
                                function=self._function.name,
                            )
                        )
                return

        for argument in [*node.args, *(kw.value for kw in node.keywords)]:
            source, sanitisers = self._taint_of(argument)
            if source is None:
                continue

            how = [self._how_reached(argument)]
            applied = list(sanitisers)
            if category == "command":
                shell = self._shell_enabled(node)
                how.append("shell=True" if shell else "shell=False")
                if not shell and isinstance(argument, ast.List | ast.Tuple):
                    # An argv element with no shell cannot introduce a
                    # second command: there is no shell to parse the
                    # metacharacters. That is a mitigating control, not
                    # merely context, so it belongs with the sanitisers
                    # where FlowIsUnsanitised will see it.
                    applied.append("argv element with shell=False")

            self.flows.append(
                Flow(
                    source=source,
                    sink=name,
                    sink_category=category,
                    steps=tuple(how),
                    sanitisers=tuple(applied),
                    line=node.lineno,
                    function=self._function.name,
                )
            )
            return


def _is_entry(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if function.name in ENTRY_NAMES:
        return True
    for decorator in function.decorator_list:
        name = dotted_name(decorator)
        tail = name.split(".")[-1].lower() if name else ""
        if tail in ENTRY_DECORATORS:
            return True
    return False


@dataclass
class ModuleAnalysis:
    """Everything found in one file."""

    path: str
    flows: list[Flow] = field(default_factory=list)
    functions: dict[str, FunctionFacts] = field(default_factory=dict)
    parse_error: str | None = None


def analyse_source(source: str, *, path: str) -> ModuleAnalysis:
    """Analyse one Python file."""
    analysis = ModuleAnalysis(path=path)
    lines = source.splitlines()
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as error:
        # Reported rather than swallowed. A file that could not be parsed
        # was not analysed, and that is a coverage gap, not a clean file.
        analysis.parse_error = f"line {error.lineno}: {error.msg}"
        return analysis

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        analyser = _FunctionAnalyser(node, path)
        for statement in node.body:
            analyser.visit(statement)

        for flow in analyser.flows:
            if 1 <= flow.line <= len(lines):
                flow.excerpt = lines[flow.line - 1].strip()[:200]
        analysis.flows.extend(analyser.flows)
        analysis.functions[node.name] = FunctionFacts(
            name=node.name,
            qualified=f"{path}::{node.name}",
            line=node.lineno,
            calls=analyser.calls,
            call_argument_sources=analyser.call_argument_sources,
            is_entry=_is_entry(node),
            tainted_parameters=analyser.tainted_parameters,
        )

    return analysis


def propagate(analysis: ModuleAnalysis) -> None:
    """Carry taint one level from callers into helpers.

    Covers the common `route handler -> helper -> sink` shape. One level
    only, and the limitation is deliberate: each further level multiplies
    the false positives without a proper dataflow framework behind it.

    The caller's *source* is carried through, not just its name. A flow
    that reads "parameter 'host'" does not establish attacker influence,
    however it was reached; one that reads "HTTP query parameter, reaching
    ping via route_ping" does.
    """
    helpers = {
        name: facts for name, facts in analysis.functions.items() if facts.tainted_parameters
    }
    if not helpers:
        return

    for caller in analysis.functions.values():
        if not caller.is_entry:
            continue
        for called in caller.calls:
            helper = helpers.get(called)
            if helper is None:
                continue

            passed = caller.call_argument_sources.get(called, ())
            carried = next(
                (
                    (source, sanitisers)
                    for position, (source, sanitisers) in enumerate(passed)
                    if source is not None
                    and position in helper.tainted_parameters
                    and not source.startswith("parameter '")
                ),
                None,
            )
            if carried is None:
                # The caller passed nothing tainted into the parameter
                # that reaches the sink, so there is no flow to carry.
                # Leaving the helper's own flow as-is is correct: it
                # begins at a parameter and says so.
                continue

            origin, caller_sanitisers = carried
            for flow in analysis.flows:
                if flow.function == helper.name and flow.source.startswith("parameter '"):
                    flow.source = origin
                    # Prepend the call path; keep how the value reaches the
                    # sink, which is the part that decides exploitability.
                    flow.steps = (caller.name, helper.name, *flow.steps)
                    # Sanitisers applied by the caller protect the helper
                    # just as much as ones applied inside it. Dropping
                    # them reported `ping(shlex.quote(value))` as an
                    # injection.
                    flow.sanitisers = tuple(dict.fromkeys([*caller_sanitisers, *flow.sanitisers]))


def reachable_functions(analysis: ModuleAnalysis) -> set[str]:
    """Functions reachable from an entry point, by call name.

    Breadth-first over the call graph with a depth cap. Only names are
    matched, which over-approximates - two functions with the same name in
    different modules are conflated. Over-approximating reachability is
    the safer direction: it risks a finding a human must dismiss, rather
    than hiding one.
    """
    reachable: set[str] = set()
    frontier = [(name, 0) for name, f in analysis.functions.items() if f.is_entry]
    reachable.update(name for name, _ in frontier)

    while frontier:
        name, depth = frontier.pop()
        if depth >= MAX_DEPTH:
            continue
        facts = analysis.functions.get(name)
        if facts is None:
            continue
        for called in facts.calls:
            if called in analysis.functions and called not in reachable:
                reachable.add(called)
                frontier.append((called, depth + 1))

    return reachable


def iter_python_files(root: Path) -> Iterator[Path]:
    """Python files worth analysing, deterministically ordered."""
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "build", "dist"}
    for path in sorted(root.rglob("*.py")):
        if any(part in skip for part in path.relative_to(root).parts):
            continue
        yield path


@dataclass
class AnalysisReport:
    modules: list[ModuleAnalysis] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)

    @property
    def parse_errors(self) -> Sequence[str]:
        return [f"{m.path}: {m.parse_error}" for m in self.modules if m.parse_error is not None]

    @property
    def is_partial(self) -> bool:
        return bool(self.unreadable) or bool(self.parse_errors)


def analyse_tree(root: Path) -> AnalysisReport:
    """Analyse every Python file under `root`."""
    report = AnalysisReport()
    for path in iter_python_files(root):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            report.unreadable.append(f"{path.name}: {error}")
            continue
        analysis = analyse_source(source, path=path.relative_to(root).as_posix())
        propagate(analysis)
        report.modules.append(analysis)
    return report
