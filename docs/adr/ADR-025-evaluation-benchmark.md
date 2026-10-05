# ADR-025: Confidence weights are measured, not argued

## Status
Accepted. Discharges the note left in `config/confidence.toml` at M3: *"The
weights are a starting point, not a result. They should be tuned against the
benchmark at M14."*

## Context
Every number CyberRE reports comes from `config/confidence.toml`. Those
numbers were reasoned about carefully and never checked against anything.
A weight set that is merely plausible produces scores that are merely
plausible, and "0.93 confidence" is a stronger claim than "this looks bad"
precisely because it implies measurement. Until now it implied one that had
not happened.

Three things have to be true for a benchmark to be worth running.

**It must contain hard negatives.** A corpus of obviously injectable code
measures nothing: a scanner that flags every `subprocess` call scores
perfectly on it. The cases that decide whether the weights are any good are
the ones that look vulnerable and are not - a parameterised query, a
`shlex.quote`d argument, a flow into dead code, a tainted value that reaches
a sink that is not a sink.

**Tuning and reporting cannot use the same cases.** Weights fitted to a
corpus will score well on that corpus by construction. Without a holdout,
the benchmark measures how hard the tuner tried.

**Accuracy is the wrong headline metric.** CyberRE does not output booleans;
it outputs confidences. A system that is right 90% of the time but says
0.99 every time is badly broken in a way accuracy cannot see. What matters
is *calibration*: whether the things scored 0.9 are true about 90% of the
time.

## Decision
A new `cyberre/evaluation/` package: a labelled corpus, a harness that runs
the real pipeline over it, metrics, and a weight tuner.

**The corpus drives the data-flow analyser, not Semgrep.** The taint
analyser is pure standard library, so the benchmark is deterministic,
offline, free, and runs in the always-on tier rather than nightly. Semgrep
and Ghidra variants belong in `realtool`, where a benchmark result depends
on a version of something outside the repository.

**Metrics are precision, recall, F1 *and* calibration** - Brier score and
expected calibration error. The tuner's objective is a combination, so it
cannot buy recall by scoring everything 1.0.

**Cases are split by hash of their identifier**, not shuffled, so the split
is stable across runs and a case cannot migrate from holdout to training
when someone adds a case.

**Tuned weights are proposed, never written.** The tuner emits a candidate
`confidence.toml` and a comparison; a human bumps the version and commits
it. An automatic retune would mean a finding's score silently depends on
when it was run.

## Consequences
The benchmark can report that the current weights are *worse* than an
alternative, and that is the point of building it. It can also report that
the corpus is too small to distinguish them - with 20-odd cases a difference
of 0.01 in F1 is noise, and the harness says so rather than ranking on it.

A corpus this size does not establish an absolute false-positive rate for
CyberRE in the field. It establishes a *regression floor*: a change that
makes detection worse fails a test. That is the honest claim and the one the
tests assert.

Benchmark results are not evidence and cannot become findings. They describe
the tool, not an artefact. `tool_reliability` in the confidence formula is
the one place a measured benchmark number legitimately enters scoring, and
it enters as a property of a capability, never of a run.
