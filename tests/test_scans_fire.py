"""G2-meta-scans-kartikeya — the meta-scan: every AST/grep-guard helper this
suite carries has been shown to catch something, by a test that *calls it*.

*A scan that has never fired has not been shown to check anything* is this
repo's own rule — `tests/test_readme_versions.py` and
`tests/test_changelog_dedup_docstring_matches_tree.py` both say it in their
docstrings, and each plants a synthetic violation to prove its guard fires.
This file is that rule turned into a test that reads the *other* test files:
it finds every module-level helper in ``tests/`` that is shaped like a
violation-scanner and asserts that some planted-violation test in the *same
file* runs that helper — directly, or through another helper it calls.

This file is not a fresh design: it is homestead-ledger's
`tests/test_scans_fire.py` (itself copied from homestead-health's and the
engine's), ported for its shape and re-grounded against this repo's own test
files. The discovery rule and the plant rule below are theirs, verified here
rather than re-derived, because a meta-scan that disagreed between repos about
what counts as "planted" would be exactly the kind of drift the fleet sweep
exists to close. Where a docstring below names a real file, it names one of
*this* repo's; where the original named a homestead file the port could not
re-ground, the synthetic plant that stood beside it is kept and the citation
is dropped.

**Discovery is structural, not a naming convention.** A rule that only
matched a leading underscore or a stem list would miss a public
`check_payload_reach(...)` (an AST-walking scan spelled the way a helper
meant to be imported is spelled) and a grep-shaped `forbidden_word_hits(path)`
that reads a file and asks `"payload" in text` with no `ast` and no matching
stem at all — both are planted below, alongside the real thing. So the rule
is what a scan *does*:

* it parses or walks source (`ast.parse`, `ast.walk`), **or**
* it matches text with a pattern (`re.search`/`findall`/`finditer`/`match`/
  `fullmatch`/`compile`, or a module-level compiled pattern's `.search(…)`),
  **or**
* it reads a file's text (`.read_text()`/`.read_bytes()`) *and* asks a
  membership question of it (`x in text`, `x not in parts`) — the grep shape
  with no regex in it, **or**
* it walks a **module-level list of forbidden words** and asks membership of
  each — `any(c in text for c in NON_SUPPRESSED_CREDENTIALS)`. This is the
  shape `tests/test_release_wiring.py::_names_a_non_suppressed_credential`
  is: it reads no file (its caller hands it the value), compiles no pattern
  and parses no source, so none of the three rules above see it — and it is
  the whole enforcement of "no GITHUB_TOKEN in the release job", the check
  that jeles lost three releases to not having. The rule is narrow on
  purpose — the iteration must be over a module-level *collection* constant
  and the body must ask an `in` question — because "references a constant
  and says `in` somewhere" would report `tests/test_public_surface.py`'s
  ordinary `for name in SANDBOX_SEAM: assert name in doc`, and a meta-scan
  that cries wolf gets an allowlist bolted to it and stops meaning anything.
  (That test asks its question of a docstring it never read from disk, so
  the inline half below does not report it either; the boundary is the same
  one, drawn twice.)
* it is handed the word list by its caller and filters it by membership —
  `[term for term in terms if term in haystack]` — the same grep with the
  list hoisted one frame up.

The name stems and the `_is_` prefix are kept on top of that, not instead of
it: they still catch helpers that hand their work to a caller. Discovery is a
union, so it is strictly wider than either half alone. Measured against this
repo on 2026-09-12: the stem list matched no real helper here at all (this
suite's helpers are named `_yaml`, `_vendored`, `_released_sentence`, and so
on, not `_offenders`), so every real finding below came from the structural
half. The stems stay because the sibling suites lean on them and a port that
quietly narrowed the rule would be drift of its own.

**Having a plant means a plant test calls the scan.** A test called
`test_the_guard_fires` that never touches the guard has not fired it — the
word in a test's name is not the evidence. A helper counts as planted only
when a `test_*` function whose name or docstring carries `plant`, `fires` or
`catches` reaches it — through the module's own helpers as well as directly,
so a plant that calls a wrapper has exercised the parser underneath it too.
Both halves are planted below: the name-only plant test (a counter-example
that must still be reported) and the call-through-a-helper case (which must
not). This repo had the name-only case live when this file was ported:
`test_changelog_dedup_docstring_matches_tree.py`'s plant test carried
"catches" in its name and asserted the stale phrase against a string it
built, never calling `_module_docstring` — so the parser that reads the real
docstring had never been shown to work. Fixed in the same change.

**Honest about what it still cannot see.** A helper that reaches `ast.parse`
through an alias (`from ast import parse as p`), one that shells out to
`grep`, or one whose whole check is a comparison of two already-read strings
with no membership test and no pattern, is outside the rule above. Closing
those needs an interpreter, not a reader; this scan is the AST-grep half, not
a promise that it sees everything a scan could be shaped like. The hash pin
in `tests/test_vendor_pins.py` is exactly that last shape — a read, a digest,
an equality — and is planted on its own terms, not by this file.

**The meta-scan is itself planted.** Every helper here is proven by a plant
below, and the last test in this file turns both halves on this very file to
show it passes the rule it enforces on everyone else. The two top-level
sweeps take the directory they sweep as an argument for that reason: a plant
can stage a tests directory in `tmp_path` and watch the real sweep report it.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

#: The name of this file, excluded from the sweeps it runs: its own helpers
#: are proven by `test_the_meta_scan_passes_its_own_rule` below, which turns
#: the same two rules on this file directly.
_THIS_FILE = Path(__file__).name

#: Word-stems the sibling suites' scan helpers use, split on "_" so
#: `_record_synced_offenders`-style names (offenders is the *last* word) and
#: `_reads_a_jsonl_path_with_bare_json_loads`-style names (reads is the
#: *first*) both match without over-firing on unrelated names.
_NAME_TOKENS = frozenset(
    {
        "scan",
        "scans",
        "reads",
        "calls",
        "offenders",
        "uses",
        "check",
        "checks",
        "guard",
        "guards",
    }
)

#: The convention this repo actually uses for "this scan was shown to fire on
#: a planted violation" — read off the real test names
#: (`test_the_check_actually_catches_a_stale_version_literal`,
#: `test_the_stale_claim_check_actually_catches_a_stale_docstring`), not
#: guessed. The word is necessary; calling the scan is what makes it count.
_PLANT_NAME_WORDS = ("plant", "fires", "catches")

#: In a *docstring*, only "plant" counts. "fires" and "catches" are ordinary
#: prose about the thing under test — `tests/test_release_wiring.py`'s
#: `test_release_automation_uses_a_non_suppressed_credential_everywhere` has
#: a docstring reading "no tag workflow fires, nothing publishes", about
#: GitHub's event suppression and not about a plant at all, and it calls the
#: very credential scan that had no plant. A rule that counted "fires" in a
#: docstring would have cleared that scan on the strength of prose about
#: something else. A word that common in a repo's own subject matter cannot
#: also be its evidence of a plant.
_PLANT_DOC_WORDS = ("plant",)

#: Pattern-matching methods. Matched on the attribute name alone, so both
#: `re.search(...)` and a module-level `_VERSION_RE.search(...)` count — a
#: compiled pattern is the same scan with the compile hoisted.
_MATCH_CALLS = frozenset(
    {"search", "findall", "finditer", "match", "fullmatch", "compile"}
)

#: Reading a file's text through `pathlib`. The grep half of a grep-shaped
#: scan, in the spelling this suite reaches for first.
_TEXT_READS = frozenset({"read_text", "read_bytes"})

#: The same read through an already-open handle — `open(p).read()` and the
#: `with open(p) as f: f.read()` spelling of it. A rule that knew only
#: `_TEXT_READS` cleared those, which was never a documented boundary — only
#: a spelling it had not been shown (homestead audit, 2026-09-11).
_HANDLE_READS = frozenset({"read", "readlines", "readline"})

#: Wrappers a read may be decoded or normalised through before the
#: membership question is asked — `p.read_bytes().decode()` is the same read
#: of the same file, and the text it yields is the text actually read.
_TEXT_WRAPPERS = frozenset({"decode", "strip", "lower", "upper", "casefold"})

#: Reading a module's source without naming a path. `inspect.getsource(obj)`
#: returns the real file's text and is a read of it.
_SOURCE_READS = frozenset({"getsource", "getsourcelines"})


def _is_open_call(expr: ast.AST) -> bool:
    """A builtin `open(...)`, however its mode and encoding are spelled."""
    return (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == "open"
    )


def _open_handles(node: ast.AST) -> frozenset[str]:
    """Every local name bound to an `open(...)` — `with open(p) as f` and
    `f = open(p)` alike — so `f.read()` is recognised as the file read it
    is."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.withitem) and _is_open_call(sub.context_expr):
            if isinstance(sub.optional_vars, ast.Name):
                names.add(sub.optional_vars.id)
        elif isinstance(sub, ast.Assign) and _is_open_call(sub.value):
            names.update(t.id for t in sub.targets if isinstance(t, ast.Name))
    return frozenset(names)


def _is_read_call(expr: ast.AST, handles: frozenset[str] = frozenset()) -> bool:
    """True if `expr` itself reads a real file's text — `.read_text()`/
    `.read_bytes()`, `open(...).read()` or an open handle's `.read()`, or
    `inspect.getsource(...)` — through any number of decoding wrappers."""
    if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.Attribute):
        return False
    attr = expr.func.attr
    if attr in _TEXT_READS or attr in _SOURCE_READS:
        return True
    if attr in _HANDLE_READS:
        return _is_open_call(expr.func.value) or (
            isinstance(expr.func.value, ast.Name) and expr.func.value.id in handles
        )
    if attr in _TEXT_WRAPPERS:
        return _is_read_call(expr.func.value, handles)
    return False


def _calls_in(node: ast.AST):
    """Every `Call` anywhere inside `node`."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            yield sub


def _walks_source(node: ast.AST) -> bool:
    """True if the body calls `ast.parse(...)` or `ast.walk(...)` — the shape
    of a scan that reads source rather than trusting an already-parsed tree."""
    return any(
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "ast"
        and call.func.attr in ("parse", "walk")
        for call in _calls_in(node)
    )


def _matches_text(node: ast.AST) -> bool:
    """True if the body runs a pattern over text — `re.search(...)`, a
    compiled pattern's `.finditer(...)`, or a bare `compile(...)`."""
    for call in _calls_in(node):
        if isinstance(call.func, ast.Attribute) and call.func.attr in _MATCH_CALLS:
            return True
        if isinstance(call.func, ast.Name) and call.func.id == "compile":
            return True
    return False


def _reads_file_text(node: ast.AST) -> bool:
    """True if the body reads a file's text itself, in any of the spellings
    `_is_read_call` knows."""
    handles = _open_handles(node)
    return any(_is_read_call(call, handles) for call in _calls_in(node))


def _tests_membership(node: ast.AST) -> bool:
    """True if the body asks `x in y` / `x not in y` anywhere — the grep
    question, once the text is in hand."""
    return any(
        isinstance(sub, ast.Compare)
        and any(isinstance(op, (ast.In, ast.NotIn)) for op in sub.ops)
        for sub in ast.walk(node)
    )


def _module_collection_constants(tree: ast.Module) -> frozenset[str]:
    """Every module-level `ALL_CAPS` name bound to a collection literal (or to
    `frozenset(...)`/`set(...)`/`tuple(...)`/`list(...)`) — the shape a
    forbidden-word list is written in, in this repo
    (`NON_SUPPRESSED_CREDENTIALS`) and its siblings."""
    found: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not (isinstance(target, ast.Name) and target.id.isupper()):
                continue
            value = node.value
            if isinstance(value, (ast.Set, ast.List, ast.Tuple)) or (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id in ("frozenset", "set", "tuple", "list")
            ):
                found.add(target.id)
    return frozenset(found)


def _scans_a_word_list(node: ast.AST, constants: frozenset[str]) -> bool:
    """True if the body iterates one of `constants` and asks a membership
    question inside that iteration — the forbidden-word-list scan."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.For):
            iterables, body = [sub.iter], sub.body
        elif isinstance(
            sub, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            iterables, body = [g.iter for g in sub.generators], [sub]
        else:
            continue
        if not any(isinstance(it, ast.Name) and it.id in constants for it in iterables):
            continue
        if any(_tests_membership(part) for part in body):
            return True
    return False


def _decorator_name(dec: ast.AST) -> str:
    """A decorator's own terminal name: `pytest.fixture` -> "fixture",
    `pytest.mark.usefixtures(...)` -> "usefixtures"."""
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return ""


def _filters_by_membership(node: ast.AST) -> bool:
    """True if the body loops over something and keeps the items that are
    (or are not) *in* something else — `[term for term in terms if term in
    haystack]`.

    `_scans_a_word_list` above wants the iterable to be a module-level
    constant, which is right for a helper owning its own forbidden list. A
    helper handed the terms as an argument is the same grep with the list
    hoisted to the caller. Narrow the same way: the membership question must
    be asked *of the loop variable itself*, so iterating a table and
    asserting something about a result is still not a scan.
    """
    for sub in ast.walk(node):
        if isinstance(sub, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            targets = {
                gen.target.id
                for gen in sub.generators
                if isinstance(gen.target, ast.Name)
            }
            conditions = [cond for gen in sub.generators for cond in gen.ifs]
        elif isinstance(sub, ast.For) and isinstance(sub.target, ast.Name):
            targets, conditions = {sub.target.id}, list(sub.body)
        else:
            continue
        for condition in conditions:
            for inner in ast.walk(condition):
                if (
                    isinstance(inner, ast.Compare)
                    and any(isinstance(op, (ast.In, ast.NotIn)) for op in inner.ops)
                    and isinstance(inner.left, ast.Name)
                    and inner.left.id in targets
                ):
                    return True
    return False


def _is_fixture(node: ast.FunctionDef) -> bool:
    """`@pytest.fixture` — setup, not a scan, whatever it reads.

    Matched on the decorator's *own terminal name*, not on the word
    "fixture" appearing anywhere in its dump: `@pytest.mark.usefixtures(...)`
    carries that word and is not a fixture, and reading it as one would
    silently exempt the whole decorated test from both halves of this file.
    """
    return any(_decorator_name(dec) == "fixture" for dec in node.decorator_list)


def _is_scan_helper(
    node: ast.FunctionDef, constants: frozenset[str] = frozenset()
) -> bool:
    """A module-level helper counts as a scan/guard if it is shaped like one
    (walks source, matches a pattern, reads a file and asks a membership
    question of it, walks a module-level word list asking membership of
    each, or filters its caller's list by membership) or its name carries
    one of the sibling suites' stems.

    Deliberately *not* conditioned on a leading underscore: a public
    `check_payload_reach` is the same scan with a different name.
    """
    name = node.name
    if name.startswith(("test_", "__")):
        return False
    if _is_fixture(node):
        return False
    if name.startswith("_is_"):
        return True
    if _NAME_TOKENS & set(name.strip("_").split("_")):
        return True
    return (
        _walks_source(node)
        or _matches_text(node)
        or (_reads_file_text(node) and _tests_membership(node))
        or _scans_a_word_list(node, constants)
        or _filters_by_membership(node)
    )


def _is_plant_test(node: ast.FunctionDef) -> bool:
    """True if `node` is a planted-violation test by this repo's convention:
    a plant word in its name, or the narrower "plant" in its docstring."""
    name = node.name.lower()
    doc = (ast.get_docstring(node) or "").lower()
    return any(word in name for word in _PLANT_NAME_WORDS) or any(
        word in doc for word in _PLANT_DOC_WORDS
    )


def _module_helpers(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    """Every module-level, non-test function in one tests module, by name."""
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("test_")
    }


def _scan_helpers(source: str) -> list[str]:
    """Every module-level scan-helper function name in one tests module."""
    tree = ast.parse(source)
    constants = _module_collection_constants(tree)
    return sorted(
        name
        for name, node in _module_helpers(tree).items()
        if _is_scan_helper(node, constants)
    )


def _direct_calls(node: ast.AST, known: dict[str, ast.FunctionDef]) -> set[str]:
    """The module's own helpers this node calls by bare name."""
    return {
        call.func.id
        for call in _calls_in(node)
        if isinstance(call.func, ast.Name) and call.func.id in known
    }


def _helpers_the_plants_exercise(source: str) -> set[str]:
    """Every helper reachable from a planted-violation test in this module.

    A test counts as a plant test when its **name** carries one of
    `_PLANT_NAME_WORDS`, or its docstring carries one of the narrower
    `_PLANT_DOC_WORDS`; from there the reach is transitive through the
    module's own helpers, because a plant that calls a wrapper has exercised
    the helper underneath it just as surely as if it had called it by hand.
    """
    tree = ast.parse(source)
    helpers = _module_helpers(tree)
    reached: set[str] = set()
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef) and node.name.startswith("test_")):
            continue
        if not _is_plant_test(node):
            continue
        pending = list(_direct_calls(node, helpers))
        while pending:
            name = pending.pop()
            if name in reached:
                continue
            reached.add(name)
            pending.extend(_direct_calls(helpers[name], helpers))
    return reached


def _unplanted_scan_helpers(source: str) -> list[str]:
    """The scan helpers in one tests module that no planted-violation test in
    the same module ever calls."""
    exercised = _helpers_the_plants_exercise(source)
    return [name for name in _scan_helpers(source) if name not in exercised]


#: A shared scan module, if a suite grows one. Not a `test_*.py` file, so it
#: holds no plant tests of its own and the same-file rule above cannot reach
#: it — while `_global_scan_helper_names()` would happily use its helpers to
#: *clear* inline scans elsewhere. A helper that can excuse a test and can
#: never be made to fire is the exact asymmetry this file exists to forbid,
#: so a shared module is swept too, against plants anywhere in `tests/`.
#: This repo has no `tests/_scans.py` today (measured 2026-09-12); the sweep
#: is kept, and planted against a staged one, so that the day one appears it
#: is covered from its first commit rather than found by the next audit.
SHARED_SCANS_NAME = "_scans.py"


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """`from _scans import terms_found as tf` -> `{"tf": "terms_found"}`,
    for imports anywhere in the module, function bodies included."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
    return aliases


def _called_names(node: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Every name `node` calls: bare (resolved through `aliases`) or through
    an attribute — `helper(...)`, `tf(...)`, `module.helper(...)` are one
    delegation by three routes."""
    names: set[str] = set()
    for call in _calls_in(node):
        if isinstance(call.func, ast.Name):
            names.add(aliases.get(call.func.id, call.func.id))
        elif isinstance(call.func, ast.Attribute):
            names.add(call.func.attr)
    return names


def _names_the_plants_call(source: str) -> frozenset[str]:
    """Every name a planted-violation test in this module calls — directly,
    or through the module's own helpers, whichever module actually defines
    the name it calls."""
    tree = ast.parse(source)
    helpers = _module_helpers(tree)
    aliases = _import_aliases(tree)
    called: set[str] = set()
    walked: set[str] = set()
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef) and node.name.startswith("test_")):
            continue
        if not _is_plant_test(node):
            continue
        called |= _called_names(node, aliases)
        pending = list(_direct_calls(node, helpers))
        while pending:
            name = pending.pop()
            if name in walked:
                continue
            walked.add(name)
            called |= _called_names(helpers[name], aliases)
            pending.extend(_direct_calls(helpers[name], helpers))
    return frozenset(called)


def _unplanted_shared_scan_helpers(tests_dir: Path = TESTS_DIR) -> list[str]:
    """The scan helpers in `tests/_scans.py` that no planted-violation test
    anywhere in `tests/` ever calls. Cross-module by construction: the
    shared module has no plant tests of its own, and the plant that proves a
    shared helper belongs with the caller that relies on it. Empty when
    there is no shared module."""
    shared = tests_dir / SHARED_SCANS_NAME
    if not shared.exists():
        return []
    exercised: set[str] = set()
    for path in sorted(tests_dir.glob("test_*.py")):
        if path.name == _THIS_FILE:
            continue
        exercised |= _names_the_plants_call(path.read_text(encoding="utf-8"))
    return [
        name
        for name in _scan_helpers(shared.read_text(encoding="utf-8"))
        if name not in exercised
    ]


def _offenders(tests_dir: Path = TESTS_DIR) -> list[str]:
    """Every tests/*.py file that defines a scan helper no plant test in the
    same file calls — and `tests/_scans.py` if there is one, whose helpers
    are shared and so are held to a plant anywhere in `tests/`."""
    offenders = []
    for path in sorted(tests_dir.glob("test_*.py")):
        if path.name == _THIS_FILE:
            continue  # this file's own helpers are proven below, not here
        unplanted = _unplanted_scan_helpers(path.read_text(encoding="utf-8"))
        if unplanted:
            offenders.append(f"{path.name}: {unplanted}")
    shared_unplanted = _unplanted_shared_scan_helpers(tests_dir)
    if shared_unplanted:
        offenders.append(f"{SHARED_SCANS_NAME}: {shared_unplanted}")
    return offenders


def test_every_scan_helper_has_a_planted_violation_test():
    """The house rule, run for real: no `tests/*.py` file may carry an
    AST/grep-guard helper that no planted-violation test in the same file
    actually runs.

    When this file was ported (2026-09-12) it reported two real helpers:
    `test_release_wiring.py::_names_a_non_suppressed_credential` (the
    word-list shape; no plant at all) and
    `test_changelog_dedup_docstring_matches_tree.py::_module_docstring`
    (a plant test in name only — it never called the helper). Both were
    planted in the same change; this test is what keeps them that way."""
    offenders = _offenders()
    assert not offenders, (
        "these test files define a scan helper (it walks source, matches a "
        "pattern, reads a file and asks a membership question of it, or walks "
        f"a word list asking membership of each — or its name carries one of "
        f"{sorted(_NAME_TOKENS)}) that no test naming plant/fires/catches ever "
        "calls — a scan that has never fired has not been shown to check "
        f"anything: {offenders}"
    )


# ── the discovery half, planted twice: AST-shaped and grep-shaped ────────────


def _write(tmp_path: Path, name: str, body: str) -> str:
    """A fake tests module on disk, read back the way `_offenders()` reads a
    real one."""
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path.read_text(encoding="utf-8")


def test_the_meta_scan_finds_an_ast_shaped_scan_whatever_it_is_named(tmp_path):
    """Planted: a scan that walks `ast` under a **public** name. A rule that
    required a leading underscore would miss `check_payload_reach` — the same
    scan, spelled the way a helper meant to be imported is spelled — and its
    missing plant would go unreported."""
    source = _write(
        tmp_path,
        "test_planted_ast_shaped_scan.py",
        "import ast\n"
        "\n"
        "def check_payload_reach(source):\n"
        "    return [n for n in ast.walk(ast.parse(source))\n"
        "            if isinstance(n, ast.Attribute) and n.attr == 'payload']\n"
        "\n"
        "def test_nothing_reaches_a_payload():\n"
        "    assert not check_payload_reach('x = 1\\n')\n",
    )

    assert _scan_helpers(source) == ["check_payload_reach"], (
        "an ast.parse/ast.walk scan must be found under any name, public or "
        f"private; got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["check_payload_reach"], (
        "and with no planted-violation test in the file it must be reported"
    )


def test_the_meta_scan_finds_a_grep_shaped_scan(tmp_path):
    """Planted: a scan with no `ast` in it at all — `path.read_text()` and an
    `in`. A discovery rule that only knew about `ast` would clear a file
    whose only guard is this shape."""
    source = _write(
        tmp_path,
        "test_planted_grep_shaped_scan.py",
        "def forbidden_word_hits(path):\n"
        "    return 'payload' in path.read_text(encoding='utf-8')\n"
        "\n"
        "def test_no_module_says_payload(tmp_path):\n"
        "    probe = tmp_path / 'm.py'\n"
        "    probe.write_text('x = 1\\n', encoding='utf-8')\n"
        "    assert not forbidden_word_hits(probe)\n",
    )

    assert _scan_helpers(source) == ["forbidden_word_hits"], (
        "a read_text()+`in` scan is a scan; the name carries none of the "
        f"stems, which is the point. Got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["forbidden_word_hits"]


def test_a_fixture_is_not_mistaken_for_a_scan(tmp_path):
    """The other side of the same honesty: `@pytest.fixture` setup that reads
    a file must not be reported, or the meta-scan cries wolf on every suite
    that stages a config in `tmp_path` — `tests/test_env_deny.py`'s
    `custom_config` and `tests/test_sandbox.py`'s `vendored_default` are
    exactly that shape here."""
    source = _write(
        tmp_path,
        "test_planted_fixture_only.py",
        "import pytest\n"
        "\n"
        "@pytest.fixture\n"
        "def custom_config(tmp_path):\n"
        "    (tmp_path / 'seed').write_text('x', encoding='utf-8')\n"
        "    return 'seed' in (tmp_path / 'seed').read_text(encoding='utf-8')\n"
        "\n"
        "def test_it(custom_config):\n"
        "    assert custom_config\n",
    )
    assert _scan_helpers(source) == []


# ── the plant half: naming a test "fires" is not having fired ────────────────


def test_the_plant_check_requires_the_plant_test_to_call_the_scan(tmp_path):
    """The counter-example, planted. A file whose only "plant" is a test
    *named* `test_the_scan_fires` and whose body never touches the scan must
    still be reported — a plant word in a name is not a plant. This is the
    live case the port found in
    `test_changelog_dedup_docstring_matches_tree.py`."""
    source = _write(
        tmp_path,
        "test_planted_name_only_plant.py",
        "import ast\n"
        "\n"
        "def _payload_reaches(tree):\n"
        "    return [n for n in ast.walk(tree)\n"
        "            if isinstance(n, ast.Attribute) and n.attr == 'payload']\n"
        "\n"
        "def test_the_scan_fires_on_a_planted_violation():\n"
        "    '''Says it plants. Plants nothing.'''\n"
        "    assert True\n",
    )

    assert _scan_helpers(source) == ["_payload_reaches"]
    assert _unplanted_scan_helpers(source) == ["_payload_reaches"], (
        "a plant test that never calls the scan has not fired it; the word in "
        "the test's name is not the evidence"
    )


def test_a_plant_that_calls_the_scan_through_a_helper_clears_it(tmp_path):
    """And not over-strict: a real plant might call a wrapper rather than the
    parser underneath it. Reaching a helper through another helper is having
    exercised it, so neither may be reported."""
    source = _write(
        tmp_path,
        "test_planted_indirect_plant.py",
        "import ast\n"
        "\n"
        "def _payload_reaches(tree):\n"
        "    return [n for n in ast.walk(tree)\n"
        "            if isinstance(n, ast.Attribute) and n.attr == 'payload']\n"
        "\n"
        "def _offenders_in(source):\n"
        "    return _payload_reaches(ast.parse(source))\n"
        "\n"
        "def test_the_scan_catches_a_planted_reach():\n"
        "    assert _offenders_in('y = r.payload\\n')\n",
    )

    assert _scan_helpers(source) == ["_offenders_in", "_payload_reaches"]
    assert _unplanted_scan_helpers(source) == [], (
        "both the wrapper and the helper it calls were exercised by the plant"
    )


def test_the_plant_check_does_not_fire_on_a_real_guarded_file():
    """The whole thing against a real file of this repo's:
    `tests/test_readme_versions.py` defines one scan (`_released_sentence`,
    a compiled-pattern search over the README) and plants it
    (`test_the_check_actually_catches_a_stale_version_literal` calls it on a
    synthetic stale sentence), so the meta-scan must clear it — or it would
    be crying wolf on the very files it exists to clear."""
    source = (TESTS_DIR / "test_readme_versions.py").read_text(encoding="utf-8")
    assert _scan_helpers(source) == ["_released_sentence"], (
        "test_readme_versions.py is expected to define exactly this scan helper"
    )
    assert _unplanted_scan_helpers(source) == []


# ── the shapes the first drafts could not see ────────────────────────────────


def test_the_meta_scan_finds_a_regex_shaped_scan(tmp_path):
    """Planted: a scan whose whole body is a module-level compiled pattern
    run over text — no `ast`, no `read_text`, and a name carrying none of the
    stems. `tests/test_readme_versions.py::_released_sentence` is this shape
    here."""
    source = _write(
        tmp_path,
        "test_planted_regex_shaped_scan.py",
        "import re\n"
        "\n"
        "_BANNED = re.compile(r'innerHTML')\n"
        "\n"
        "def banned_spellings(page):\n"
        "    return _BANNED.findall(page)\n"
        "\n"
        "def test_the_page_builds_no_markup():\n"
        "    assert not banned_spellings('x')\n",
    )

    assert _scan_helpers(source) == ["banned_spellings"], (
        f"a compiled-pattern scan is a scan; got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["banned_spellings"]


def test_the_meta_scan_finds_a_forbidden_word_list_scan(tmp_path):
    """Planted: the word-list shape, and the one that was missing a real
    plant in this repo. `tests/test_release_wiring.py::
    _names_a_non_suppressed_credential` walks `NON_SUPPRESSED_CREDENTIALS`
    asking membership of a value its caller hands it — it reads no file,
    compiles no pattern, parses no source, and its name carries no stem, so
    the first three rules all clear it. It is the whole enforcement of "no
    GITHUB_TOKEN in the release job"."""
    source = _write(
        tmp_path,
        "test_planted_word_list_scan.py",
        "NON_SUPPRESSED = ('RELEASE_PLEASE_TOKEN', 'steps.app-token.outputs.token')\n"
        "\n"
        "def names_a_credential(value):\n"
        "    return any(c in str(value) for c in NON_SUPPRESSED)\n"
        "\n"
        "def test_the_job_names_one():\n"
        "    assert names_a_credential('${{ secrets.RELEASE_PLEASE_TOKEN }}')\n",
    )

    assert _scan_helpers(source) == ["names_a_credential"], (
        "a scan that walks a module-level word list asking membership of each "
        f"is a scan; got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["names_a_credential"]


def test_the_word_list_rule_does_not_fire_on_ordinary_constant_use(tmp_path):
    """The control the narrow rule exists for. A behaviour test that iterates
    a module-level table and asserts membership of a *result* is not a scan
    — `tests/test_public_surface.py`'s `for name in SANDBOX_SEAM: assert
    name in doc` is exactly this — and a rule loose enough to call it one
    gets itself allowlisted into silence."""
    source = _write(
        tmp_path,
        "test_planted_ordinary_constant_use.py",
        "SANDBOX_SEAM = ('resolve_sandbox_config', 'ensure_work_root')\n"
        "\n"
        "def surface(module):\n"
        "    return module.__doc__\n"
        "\n"
        "def test_every_name_is_declared():\n"
        "    for name in SANDBOX_SEAM:\n"
        "        assert name in ('resolve_sandbox_config', 'ensure_work_root')\n",
    )
    assert _scan_helpers(source) == []


def test_the_meta_scan_finds_a_scan_handed_its_word_list_by_the_caller(tmp_path):
    """Planted: the fifth shape. `terms_found(haystack, terms)` walks the
    *caller's* list asking membership of each — no module-level constant,
    no regex, no read, no stem in its name — so all four earlier rules clear
    it. This repo has no such helper today; the shape is kept because the
    sibling that grew one had twenty-one call sites leaning on it before its
    meta-scan could see it."""
    source = _write(
        tmp_path,
        "test_planted_caller_word_list.py",
        "def terms_found(haystack, terms):\n"
        "    return [term for term in terms if term in haystack]\n"
        "\n"
        "def test_the_log_carries_none_of_them():\n"
        "    assert not terms_found('a reference only', ('1234',))\n",
    )
    assert _scan_helpers(source) == ["terms_found"], (
        "a helper that filters the caller's terms by membership is a scan; "
        f"got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["terms_found"]


def test_the_caller_word_list_rule_does_not_fire_on_an_ordinary_filter(tmp_path):
    """The control the narrow half exists for: the membership question must
    be asked *of the loop variable itself*. A helper that filters rows by a
    field, or builds a list from a table, is ordinary code and a rule loose
    enough to report it gets an allow-list bolted on and stops meaning
    anything."""
    source = _write(
        tmp_path,
        "test_planted_ordinary_filter.py",
        "KNOWN = ('pending', 'running')\n"
        "\n"
        "def live_rows(rows):\n"
        "    return [row for row in rows if row[1] in KNOWN]\n"
        "\n"
        "def test_it():\n"
        "    assert live_rows([]) == []\n",
    )
    assert _scan_helpers(source) == []


def test_a_plant_reaches_a_shared_helper_through_an_import_alias(tmp_path):
    """A shared module's proof is cross-module, so the reach has to follow
    the routes a cross-module call actually takes: a bare name, an attribute
    (`module.helper(...)`), and the `import ... as` alias a caller may bind
    it to. A rule that only matched the bare original name would read this
    plant as calling nothing."""
    source = _write(
        tmp_path,
        "test_planted_aliased_plant.py",
        "from _scans import terms_found as tf\n"
        "import _scans\n"
        "\n"
        "def test_the_shared_scan_catches_a_planted_leak():\n"
        "    assert tf('a line naming 1234', ('1234',)) == ['1234']\n"
        "    assert _scans.other_helper('x') == []\n",
    )
    reached = _names_the_plants_call(source)
    assert "terms_found" in reached, "an aliased call is still a call"
    assert "other_helper" in reached, "and so is `module.helper(...)`"

    quiet = _write(
        tmp_path,
        "test_planted_quiet_plant.py",
        "from _scans import terms_found as tf\n"
        "\n"
        "def test_the_shared_scan_catches_a_planted_leak():\n"
        "    assert True\n",
    )
    assert _names_the_plants_call(quiet) == frozenset(), (
        "importing a helper is not calling it; the plant word in the name is "
        "not the evidence here either"
    )


def test_a_shared_scan_module_is_swept_against_plants_anywhere_in_tests(tmp_path):
    """Planted: a staged `tests/` with a `_scans.py` that no `test_*.py`
    plants — the sweep must report it, and must stop once a plant test in
    *any* module reaches the helper, by alias or by name. This repo has no
    `_scans.py` today; the sweep is planted here so that it is not found to
    have never fired on the day one appears."""
    staged = tmp_path / "tests"
    staged.mkdir()
    (staged / SHARED_SCANS_NAME).write_text(
        "def terms_found(haystack, terms):\n"
        "    return [term for term in terms if term in haystack]\n",
        encoding="utf-8",
    )
    (staged / "test_uses_it.py").write_text(
        "from _scans import terms_found\n"
        "\n"
        "def test_the_log_is_clean():\n"
        "    assert not terms_found('quiet', ('1234',))\n",
        encoding="utf-8",
    )
    assert _unplanted_shared_scan_helpers(staged) == ["terms_found"], (
        "a shared helper with no plant test anywhere in tests/ must be reported"
    )
    assert _offenders(staged) == [f"{SHARED_SCANS_NAME}: ['terms_found']"], (
        "and the top-level sweep must carry that report"
    )

    (staged / "test_plants_it.py").write_text(
        "from _scans import terms_found as tf\n"
        "\n"
        "def test_the_shared_scan_catches_a_planted_leak():\n"
        "    assert tf('a line naming 1234', ('1234',)) == ['1234']\n",
        encoding="utf-8",
    )
    assert _unplanted_shared_scan_helpers(staged) == []
    assert _offenders(staged) == []

    assert _unplanted_shared_scan_helpers(tmp_path / "no-such-tests") == [], (
        "no shared module is nothing to report, not an error"
    )


def test_the_top_level_sweep_reports_a_planted_unplanted_helper(tmp_path):
    """Planted: the sweep `test_every_scan_helper_has_a_planted_violation_test`
    runs, fired on a staged tests directory — one module with an unplanted
    grep-shaped helper, one with the same helper planted. The report names
    the file and the helper; the clean file is not named."""
    staged = tmp_path / "tests"
    staged.mkdir()
    (staged / "test_unplanted.py").write_text(
        "def forbidden_word_hits(path):\n"
        "    return 'payload' in path.read_text(encoding='utf-8')\n"
        "\n"
        "def test_no_module_says_payload(tmp_path):\n"
        "    assert not forbidden_word_hits(tmp_path / 'm.py')\n",
        encoding="utf-8",
    )
    (staged / "test_planted.py").write_text(
        "def forbidden_word_hits(path):\n"
        "    return 'payload' in path.read_text(encoding='utf-8')\n"
        "\n"
        "def test_the_scan_catches_a_planted_payload(tmp_path):\n"
        "    p = tmp_path / 'm.py'\n"
        "    p.write_text('payload', encoding='utf-8')\n"
        "    assert forbidden_word_hits(p)\n",
        encoding="utf-8",
    )
    assert _offenders(staged) == ["test_unplanted.py: ['forbidden_word_hits']"]


# ── the plant rule: "fires" in prose is not evidence of a plant ─────────────


def test_a_docstring_saying_fires_about_something_else_does_not_clear_a_scan(tmp_path):
    """The counter-example this repo has live. `tests/test_release_wiring.py`'s
    `test_release_automation_uses_a_non_suppressed_credential_everywhere` has
    a docstring saying "no tag workflow fires" — prose about GitHub's event
    suppression, not about a plant — and it calls the credential scan, which
    had no plant at all. Only "plant" counts in a docstring; "fires" and
    "catches" count in a test's name, where they are deliberate."""
    source = _write(
        tmp_path,
        "test_planted_prose_fires.py",
        "NON_SUPPRESSED = ('RELEASE_PLEASE_TOKEN',)\n"
        "\n"
        "def _names_a_credential(value):\n"
        "    return any(c in str(value) for c in NON_SUPPRESSED)\n"
        "\n"
        "def test_the_job_uses_a_real_credential():\n"
        "    '''A bot token: no tag workflow fires, nothing publishes.'''\n"
        "    assert _names_a_credential('${{ secrets.RELEASE_PLEASE_TOKEN }}')\n",
    )

    assert _scan_helpers(source) == ["_names_a_credential"]
    assert _unplanted_scan_helpers(source) == ["_names_a_credential"], (
        "prose using the word 'fires' is not a plant; the scan is still "
        "unproven and must still be reported"
    )


def test_a_docstring_that_says_planted_does_clear_the_scan(tmp_path):
    """And the other side, so the tightening cannot be a blanket refusal: a
    test whose name carries no plant word but whose docstring says it plants,
    and which calls the scan, has fired it."""
    source = _write(
        tmp_path,
        "test_planted_docstring_plant.py",
        "import ast\n"
        "\n"
        "def _reaches(tree):\n"
        "    return [n for n in ast.walk(tree) if isinstance(n, ast.Attribute)]\n"
        "\n"
        "def test_a_reach_is_reported():\n"
        "    '''Planted: a module that does reach an attribute.'''\n"
        "    assert _reaches(ast.parse('a.b\\n'))\n",
    )
    assert _scan_helpers(source) == ["_reaches"]
    assert _unplanted_scan_helpers(source) == []


# ── the inline half: a scan written directly in a test's own body ───────────
#
# Everything above reads *module-level helpers*. A guard written inline, in a
# test's own body, with nothing to name and nothing to plant, is invisible to
# it. This repo had two when this file was ported (2026-09-12):
# `tests/test_queue.py::test_no_dataclass_field_is_declared_twice` (reads
# `queue.py`, walks its AST, judges `ast.ClassDef`/`ast.AnnAssign` itself) and
# `tests/test_release_wiring.py::test_the_pr_title_check_guards_both_directions`
# (reads `pyproject.toml`, parses the workflow's embedded Python, judges an
# `ast.Assign` itself). Both were factored into a helper and planted in the
# same change. This half closes the gap: it walks every `test_*` function's
# own body for the same shapes the module-helper half already knows, holds it
# to the same "reads a file, not a string it built" requirement, and clears a
# test that delegates to a scan helper already defined (and already required
# to be planted) somewhere in `tests/` — recognized by name, whichever module
# actually owns it, since `from test_x import _helper` and a bare call to a
# same-file helper are the same delegation by a different route.
#
# "Asks a membership question of it" is held to the text actually read, not
# to anything built from it: a name bound directly to a `.read_text()`/
# `.read_bytes()` call (one level, no chain through `json.loads` or the
# like) counts; a dict key several steps removed does not. Loosening that
# would also catch `tests/test_release_wiring.py::
# test_the_version_has_exactly_one_source`'s `"version" in pyproject["project"]`
# — a `tomllib.loads` of the text, an ordinary assertion that has nothing to
# do with scanning a tree — and a rule that cries wolf on those gets an
# allowlist bolted onto it and stops meaning anything.


#: String operations that narrow text without turning it into something
#: else: `source.split("<<'PY'")[1]` is still the file's own text, and a
#: membership question of it is still a question of the tree. The list is
#: deliberately all `str`/`bytes` methods — `json.loads(...)` is a bare call
#: to a *name*, not one of these, so a dict built from a read is still
#: several steps removed and still not a scan.
_TEXT_SLICERS = _TEXT_WRAPPERS | frozenset(
    {
        "split",
        "rsplit",
        "splitlines",
        "partition",
        "rpartition",
        "replace",
        "lstrip",
        "rstrip",
        "removeprefix",
        "removesuffix",
    }
)


def _text_root(expr: ast.AST) -> ast.AST:
    """Peel subscripts and `_TEXT_SLICERS` calls off `expr` and return what
    the text ultimately came from."""
    while True:
        if isinstance(expr, ast.Subscript):
            expr = expr.value
        elif (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr in _TEXT_SLICERS
        ):
            expr = expr.func.value
        else:
            return expr


def _direct_text_names(func: ast.FunctionDef) -> frozenset[str]:
    """Local names holding the text of a file this function read — bound
    straight from the read, or from a slice of one such name through
    `_TEXT_SLICERS` alone. Nothing that turns the text into another kind of
    object (`json.loads`, `tomllib.loads`, `yaml.safe_load`) is traced, so
    `"version" in pyproject["project"]` stays the ordinary assertion it is."""
    handles = _open_handles(func)
    names: set[str] = set()
    assigns = [
        (
            [t.id for t in node.targets if isinstance(t, ast.Name)],
            _text_root(node.value),
        )
        for node in ast.walk(func)
        if isinstance(node, ast.Assign)
    ]
    for _ in range(len(assigns) + 1):  # to a fixed point; each pass adds ≥1 or stops
        grew = False
        for targets, root in assigns:
            if not targets or set(targets) <= names:
                continue
            if _is_read_call(root, handles) or (
                isinstance(root, ast.Name) and root.id in names
            ):
                names.update(targets)
                grew = True
        if not grew:
            break
    return frozenset(names)


def _is_text_source(
    expr: ast.AST, direct_names: frozenset[str], handles: frozenset[str]
) -> bool:
    root = _text_root(expr)
    return _is_read_call(root, handles) or (
        isinstance(root, ast.Name) and root.id in direct_names
    )


def _membership_on_read_text(node: ast.FunctionDef) -> bool:
    """A membership test whose text side is a file read — directly, or
    through a name `_direct_text_names` traces back to one."""
    direct_names = _direct_text_names(node)
    handles = _open_handles(node)
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Compare)
            and any(isinstance(op, (ast.In, ast.NotIn)) for op in sub.ops)
            and any(
                _is_text_source(operand, direct_names, handles)
                for operand in (sub.left, *sub.comparators)
            )
        ):
            return True
    return False


def _isinstance_against_ast_type(node: ast.AST) -> bool:
    """True if the body itself calls `isinstance(x, ast.SomeType)` (or a
    tuple containing one) — the direct judgment of a source walk, as against
    a test that merely calls `ast.parse()` and hands the tree to a scan
    helper already defined (and already planted) elsewhere."""
    for call in _calls_in(node):
        if (
            isinstance(call.func, ast.Name)
            and call.func.id == "isinstance"
            and len(call.args) == 2
        ):
            type_arg = call.args[1]
            candidates = (
                type_arg.elts if isinstance(type_arg, ast.Tuple) else [type_arg]
            )
            for candidate in candidates:
                if (
                    isinstance(candidate, ast.Attribute)
                    and isinstance(candidate.value, ast.Name)
                    and candidate.value.id == "ast"
                ):
                    return True
    return False


def _global_scan_helper_names(tests_dir: Path = TESTS_DIR) -> frozenset[str]:
    """Every scan-helper name defined anywhere in `tests/` — every
    `test_*.py` file (this one excluded — its own helpers are proven above,
    not by this rule) plus the shared `tests/_scans.py`, if there is one. A
    test that calls one of these by name — bare, or through
    `module.helper(...)` — is delegating to a helper the module-helper half
    already holds to its own plant, wherever that helper actually lives."""
    names: set[str] = set()
    paths = sorted(tests_dir.glob("test_*.py"))
    shared = tests_dir / SHARED_SCANS_NAME
    if shared.exists():
        paths.append(shared)
    for path in paths:
        if path.name == _THIS_FILE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants = _module_collection_constants(tree)
        for name, fn in _module_helpers(tree).items():
            if _is_scan_helper(fn, constants):
                names.add(name)
    return frozenset(names)


def _imported_names(tree: ast.Module) -> frozenset[str]:
    """Every name this module binds with `from ... import name` (or `as`),
    anywhere — function-body imports included, which is how a test most
    often reaches another module's helper."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
    return frozenset(names)


def _calls_any_by_name(
    node: ast.AST, bare: frozenset[str], attrs: frozenset[str] | None = None
) -> bool:
    """True if `node` delegates to a known scan helper: a bare call to one of
    `bare`, or `module.helper(...)` for one of `attrs`.

    The two sets differ on purpose. An attribute call names the module it
    comes from, so matching the attribute alone is safe. A *bare* name is
    only that helper if this module actually has it — imported, or defined
    here — otherwise a local function that happens to share a name with some
    other module's scan helper would clear every inline scan beside it.
    """
    attrs = bare if attrs is None else attrs
    for call in _calls_in(node):
        if isinstance(call.func, ast.Name) and call.func.id in bare:
            return True
        if isinstance(call.func, ast.Attribute) and call.func.attr in attrs:
            return True
    return False


def _resolvable_helpers(source: str, global_helpers: frozenset[str]) -> frozenset[str]:
    """The known scan helpers this module can reach by a *bare* name: the
    ones it imports, and the ones it defines itself."""
    tree = ast.parse(source)
    return global_helpers & (_imported_names(tree) | frozenset(_scan_helpers(source)))


def _is_inline_scan(
    node: ast.AST,
    global_helpers: frozenset[str],
    bare_helpers: frozenset[str] | None = None,
) -> bool:
    """A test body counts as an inline scan when it reads a real file and,
    in its own body — not by calling a scan helper `tests/` already defines
    somewhere — walks source and judges it directly (`ast.parse`/`ast.walk`
    plus an `isinstance` against an `ast.*` type), matches a pattern, or asks
    a membership question of the text it read.

    **Delegation clears the whole test, deliberately.** A test that calls a
    known scan helper is not reported even if it also matches a pattern of
    its own on the text it read, because in this suite that second question
    is the assertion the first one feeds:
    `tests/test_readme_versions.py::test_the_released_sentence_names_no_version_number`
    reads the README, hands it to `_released_sentence` (the planted helper)
    and then runs `_VERSION_RE.search` over the sentence that came back. The
    cost is real and named: an unplanted inline check hidden behind a
    delegated call is not seen. The alternative pushes those assertions into
    helpers for the sake of the rule, which is worse.
    """
    if not (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ):
        return False
    if _is_fixture(node):
        return False
    if not _reads_file_text(node):
        return False  # not reading a real file — a string the test built
    bare = global_helpers if bare_helpers is None else bare_helpers
    if _calls_any_by_name(node, bare, global_helpers):
        return False  # delegates to a helper already held to its own plant
    return (
        (_walks_source(node) and _isinstance_against_ast_type(node))
        or _matches_text(node)
        or _membership_on_read_text(node)
    )


def _test_functions(tree: ast.Module):
    """Every test function in a module, by the name a failure would report
    it as: module-level `def test_*`/`async def test_*`, and the methods of
    a `class Test*` — this suite writes none today, and a rule that read
    only `tree.body` could never see a scan in one on the day it does."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node
        elif isinstance(node, ast.ClassDef):
            for method in node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{node.name}::{method.name}", method


def _inline_scan_tests(source: str, global_helpers: frozenset[str]) -> list[str]:
    """Every test function in one tests module whose own body is itself a
    scan by the rule above."""
    tree = ast.parse(source)
    bare = _resolvable_helpers(source, global_helpers)
    return sorted(
        name
        for name, node in _test_functions(tree)
        if _is_inline_scan(node, global_helpers, bare)
    )


def _inline_scan_offenders(tests_dir: Path = TESTS_DIR) -> list[str]:
    """Every `file::test_name` in `tests/*.py` whose own body is itself an
    unfactored scan."""
    global_helpers = _global_scan_helper_names(tests_dir)
    offenders = []
    for path in sorted(tests_dir.glob("test_*.py")):
        if path.name == _THIS_FILE:
            continue
        for name in _inline_scan_tests(
            path.read_text(encoding="utf-8"), global_helpers
        ):
            offenders.append(f"{path.name}::{name}")
    return offenders


def test_no_test_body_is_itself_a_scan():
    """The inline half of the house rule: a guard written directly in a
    test's body, with no helper to name and plant, is invisible to the scan
    above and can never be shown to fire. Every `tests/*.py` test must
    either not be a scan by the shapes above, or delegate to a scan helper
    `tests/` already defines and plants — in the same file, another test
    module, or a shared `tests/_scans.py`.

    When this file was ported (2026-09-12) it reported two:
    `test_queue.py::test_no_dataclass_field_is_declared_twice` and
    `test_release_wiring.py::test_the_pr_title_check_guards_both_directions`.
    Both now delegate to a helper planted in their own file."""
    offenders = _inline_scan_offenders()
    assert not offenders, (
        "these tests are themselves a scan (reads a real file, then walks "
        "its source and judges it, matches a pattern, or asks a membership "
        "question of the text) with no scan helper behind them anywhere in "
        f"tests/, so the scan has never been planted: {offenders}"
    )


def test_the_inline_scan_check_finds_a_scan_written_directly_in_a_test_body(tmp_path):
    """Planted: a test file whose only guard is written inline — `ast.parse`
    plus a direct `isinstance` walk, on a file the test actually reads (via
    `tmp_path`, not a string built in place) — exactly `test_queue.py`'s
    duplicate-field check before this change factored it out. No helper
    exists anywhere for it to delegate to, so it must be reported."""
    target = tmp_path / "target.py"
    target.write_text("import banned\n", encoding="utf-8")
    source = _write(
        tmp_path,
        "test_planted_inline_scan.py",
        "import ast\n"
        "from pathlib import Path\n"
        f"TARGET = Path({str(target)!r})\n"
        "\n"
        "def test_no_banned_import_at_module_scope():\n"
        "    tree = ast.parse(TARGET.read_text('utf-8'))\n"
        "    for node in tree.body:\n"
        "        if isinstance(node, ast.Import):\n"
        "            assert 'banned' not in {a.name for a in node.names}\n",
    )
    assert _inline_scan_tests(source, frozenset()) == [
        "test_no_banned_import_at_module_scope"
    ]


def test_the_top_level_inline_sweep_reports_a_planted_inline_scan(tmp_path):
    """Planted: the sweep `test_no_test_body_is_itself_a_scan` runs, fired
    on a staged tests directory. One module scans inline with no helper
    anywhere; a second defines the helper and a third delegates to it by
    import. Only the first is reported, and it is named `file::test`."""
    staged = tmp_path / "tests"
    staged.mkdir()
    target = staged / "target.py"
    target.write_text("import banned\n", encoding="utf-8")
    (staged / "test_inline.py").write_text(
        "from pathlib import Path\n"
        f"TARGET = Path({str(target)!r})\n"
        "\n"
        "def test_no_banned_word():\n"
        "    text = TARGET.read_text(encoding='utf-8')\n"
        "    assert 'banned' not in text\n",
        encoding="utf-8",
    )
    (staged / "test_helper_home.py").write_text(
        "def banned_words_in(path):\n"
        "    return 'banned' in path.read_text(encoding='utf-8')\n"
        "\n"
        "def test_the_scan_catches_a_planted_word(tmp_path):\n"
        "    p = tmp_path / 'm.py'\n"
        "    p.write_text('banned', encoding='utf-8')\n"
        "    assert banned_words_in(p)\n",
        encoding="utf-8",
    )
    (staged / "test_delegates.py").write_text(
        "from pathlib import Path\n"
        "from test_helper_home import banned_words_in\n"
        f"TARGET = Path({str(target)!r})\n"
        "\n"
        "def test_no_banned_word():\n"
        "    text = TARGET.read_text(encoding='utf-8')\n"
        "    assert not banned_words_in(TARGET)\n"
        "    assert 'import' in text\n",
        encoding="utf-8",
    )
    assert _global_scan_helper_names(staged) == frozenset({"banned_words_in"})
    assert _inline_scan_offenders(staged) == ["test_inline.py::test_no_banned_word"]


def test_the_inline_scan_check_knows_every_spelling_of_reading_a_real_file(tmp_path):
    """Planted, one per spelling. `read_text` is the spelling this suite
    uses, so the same scan written with the builtin `open`, with a `with`
    block, through `read_bytes().decode()`, or through `inspect.getsource`
    would be cleared by a rule that knew only the one — not by a documented
    boundary, just by a spelling it had not been shown."""
    spellings = {
        "open_chain": "    text = open('x', encoding='utf-8').read()\n",
        "open_with": (
            "    with open('x', encoding='utf-8') as handle:\n"
            "        text = handle.read()\n"
        ),
        "read_bytes_decode": "    text = Path('x').read_bytes().decode()\n",
        "getsource": "    text = inspect.getsource(Path)\n",
    }
    for label, read in spellings.items():
        source = _write(
            tmp_path,
            f"test_planted_read_{label}.py",
            "import inspect\n"
            "from pathlib import Path\n"
            "\n"
            "def test_no_banned_word():\n"
            f"{read}"
            "    assert 'banned' not in text\n",
        )
        assert _inline_scan_tests(source, frozenset()) == ["test_no_banned_word"], (
            f"reading a real file via {label} is reading a real file"
        )


def test_the_inline_scan_check_follows_a_slice_of_the_text_but_not_a_parse_of_it(
    tmp_path,
):
    """The boundary the one-level rule draws, planted both ways. A `.split()`
    of the text read is still that text — `test_release_wiring.py`'s cut of
    the workflow's `<<'PY'` heredoc is exactly this shape — but a dict
    `tomllib.loads` built from it is another kind of object, and asking
    membership of *that* is the ordinary assertion this rule must not cry
    wolf on (`test_the_version_has_exactly_one_source`)."""
    sliced = _write(
        tmp_path,
        "test_planted_sliced_text.py",
        "from pathlib import Path\n"
        "\n"
        "def test_the_heredoc_names_no_export():\n"
        "    source = Path('x').read_text(encoding='utf-8')\n"
        "    block = source.split(\"<<'PY'\")[1].split('PY')[0]\n"
        "    assert 'export' not in block\n",
    )
    assert _inline_scan_tests(sliced, frozenset()) == [
        "test_the_heredoc_names_no_export"
    ]

    parsed = _write(
        tmp_path,
        "test_planted_parsed_text.py",
        "import tomllib\n"
        "from pathlib import Path\n"
        "\n"
        "def test_the_version_has_one_source():\n"
        "    pyproject = tomllib.loads(Path('x').read_text(encoding='utf-8'))\n"
        "    assert 'version' in pyproject['project']\n",
    )
    assert _inline_scan_tests(parsed, frozenset()) == [], (
        "a dict parsed out of the text is not the text; a rule that reported "
        "this gets an allow-list bolted to it and stops meaning anything"
    )


def test_the_inline_scan_check_does_not_fire_on_a_string_the_test_built(tmp_path):
    """Planted: a test that matches a pattern, but only against a string
    literal it built itself — no `.read_text()`/`.read_bytes()` anywhere.
    Not a scan of the tree, so it must not be reported."""
    source = _write(
        tmp_path,
        "test_planted_string_literal_match.py",
        "import re\n"
        "\n"
        "def test_the_greeting_has_no_banned_word():\n"
        "    assert not re.search(r'banned', 'a queue drains its own lanes')\n",
    )
    assert _inline_scan_tests(source, frozenset()) == []


def test_the_inline_scan_check_does_not_fire_on_a_fixture(tmp_path):
    """The other honesty check, held against the inline half too: a fixture
    that reads a file and asks membership of it is setup, not a scan, and
    must not be reported."""
    source = _write(
        tmp_path,
        "test_planted_inline_fixture.py",
        "import pytest\n"
        "\n"
        "@pytest.fixture\n"
        "def custom_config(tmp_path):\n"
        "    (tmp_path / 'seed').write_text('x', encoding='utf-8')\n"
        "    return 'seed' in (tmp_path / 'seed').read_text(encoding='utf-8')\n"
        "\n"
        "def test_it(custom_config):\n"
        "    assert custom_config\n",
    )
    assert _inline_scan_tests(source, frozenset()) == []


def test_a_usefixtures_marker_does_not_exempt_a_test_from_either_half(tmp_path):
    """Planted: the exemption that was not one. `@pytest.mark.usefixtures`
    carries the word "fixture", and a rule that looked for that word
    anywhere in the decorator would clear every test wearing it. The marker
    must not exempt; a real `@pytest.fixture` beside it still must."""
    marked = _write(
        tmp_path,
        "test_planted_usefixtures.py",
        "import pytest\n"
        "from pathlib import Path\n"
        "\n"
        "@pytest.mark.usefixtures('_home')\n"
        "def test_no_banned_word():\n"
        "    text = Path('x').read_text(encoding='utf-8')\n"
        "    assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(marked, frozenset()) == ["test_no_banned_word"], (
        "a usefixtures marker is not a fixture and must not exempt the test"
    )

    real = _write(
        tmp_path,
        "test_planted_real_fixture.py",
        "import pytest\n"
        "from pathlib import Path\n"
        "\n"
        "@pytest.fixture(autouse=True)\n"
        "def staged():\n"
        "    return 'banned' in Path('x').read_text(encoding='utf-8')\n",
    )
    assert _scan_helpers(real) == [], "a real @pytest.fixture is still setup"


def test_the_inline_scan_check_clears_a_test_that_delegates_to_a_known_helper(tmp_path):
    """And not over-strict: a test that reads a real file and calls a scan
    helper already known to `tests/` (wherever it actually lives — bare name
    or `module.helper(...)`) is delegating, not scanning inline, so it must
    not be reported even though it still reads a real file and still asks a
    membership question of the result."""
    target = tmp_path / "target.py"
    target.write_text("import kartikeya\n", encoding="utf-8")
    source = _write(
        tmp_path,
        "test_planted_delegating_test.py",
        "from pathlib import Path\n"
        f"TARGET = Path({str(target)!r})\n"
        "\n"
        "from test_queue import _fields_declared_twice\n"
        "\n"
        "def test_no_field_is_declared_twice():\n"
        "    duplicates = _fields_declared_twice(TARGET)\n"
        "    assert 'task_id' not in duplicates\n",
    )
    assert _inline_scan_tests(source, frozenset({"_fields_declared_twice"})) == []


def test_the_inline_scan_check_reads_class_methods_and_async_tests_too(tmp_path):
    """Planted: the two shapes a `tree.body`-only walk cannot see. This suite
    writes no test classes and no async tests today; a scan in either would
    be the same blind spot the day one is written."""
    in_a_class = _write(
        tmp_path,
        "test_planted_class_scan.py",
        "from pathlib import Path\n"
        "\n"
        "class TestTheTree:\n"
        "    def test_no_banned_word(self):\n"
        "        text = Path('x').read_text(encoding='utf-8')\n"
        "        assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(in_a_class, frozenset()) == [
        "TestTheTree::test_no_banned_word"
    ], "a scan in a test class's method is still a scan, and is named as one"

    awaited = _write(
        tmp_path,
        "test_planted_async_scan.py",
        "from pathlib import Path\n"
        "\n"
        "async def test_no_banned_word():\n"
        "    text = Path('x').read_text(encoding='utf-8')\n"
        "    assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(awaited, frozenset()) == ["test_no_banned_word"]


def test_delegating_clears_a_test_that_also_asks_its_own_question(tmp_path):
    """The boundary this rule draws, pinned rather than left to be
    rediscovered: a test that calls a known scan helper is cleared *whole*,
    including a pattern match of its own on the same text. One real test
    here depends on it (`test_readme_versions.py`'s
    `test_the_released_sentence_names_no_version_number`, which runs
    `_VERSION_RE.search` over what the planted helper returned), and
    reporting it would push the assertion into a helper for the sake of the
    rule."""
    source = _write(
        tmp_path,
        "test_planted_delegate_and_check.py",
        "import re\n"
        "from pathlib import Path\n"
        "from test_readme_versions import _released_sentence\n"
        "\n"
        "def test_the_sentence_names_no_version():\n"
        "    sentence = _released_sentence(Path('x').read_text(encoding='utf-8'))\n"
        "    assert not re.search(r'\\d+\\.\\d+\\.\\d+', sentence)\n",
    )
    assert _inline_scan_tests(source, frozenset({"_released_sentence"})) == []
    assert _inline_scan_tests(source, frozenset()) == [
        "test_the_sentence_names_no_version"
    ], "and with no helper behind it, the same body is an inline scan"


def test_a_local_function_sharing_a_helpers_name_does_not_clear_a_scan(tmp_path):
    """Planted: the shadow. Delegation is recognised by *name*, across the
    whole of `tests/`, so a module with a local function that happens to
    share a scan helper's name would have every inline scan beside it
    cleared by a call to something else entirely. A bare name only counts
    when this module imports it or defines it."""
    shadow = _write(
        tmp_path,
        "test_planted_shadowed_helper.py",
        "from pathlib import Path\n"
        "\n"
        "def _released_sentence(text):\n"
        "    return text\n"
        "\n"
        "def test_no_banned_word():\n"
        "    text = Path('x').read_text(encoding='utf-8')\n"
        "    assert _released_sentence(text)\n"
        "    assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(shadow, frozenset({"_released_sentence"})) == [
        "test_no_banned_word"
    ], "a local `_released_sentence` is not another module's `_released_sentence`"

    imported = _write(
        tmp_path,
        "test_planted_imported_helper.py",
        "from pathlib import Path\n"
        "from test_readme_versions import _released_sentence\n"
        "\n"
        "def test_no_banned_word():\n"
        "    text = Path('x').read_text(encoding='utf-8')\n"
        "    assert _released_sentence(text)\n"
        "    assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(imported, frozenset({"_released_sentence"})) == [], (
        "and the same call, of the helper this module really imported, is "
        "the delegation it looks like"
    )


def test_the_inline_scan_check_does_not_fire_on_the_real_tree():
    """The whole thing against a real file of this repo's: `test_queue.py`
    used to carry an inline dataclass-field scan and now delegates to its
    own `_fields_declared_twice`, planted in the same file — so the check
    must clear it, or it would be crying wolf on the very fix it exists to
    require."""
    global_helpers = _global_scan_helper_names()
    source = (TESTS_DIR / "test_queue.py").read_text(encoding="utf-8")
    assert "_fields_declared_twice" in global_helpers, (
        "test_queue.py is expected to define the factored-out scan helper"
    )
    assert _inline_scan_tests(source, global_helpers) == []


# ── the meta-scan is itself planted ─────────────────────────────────────────


def test_the_meta_scan_passes_its_own_rule():
    """Both halves, turned on this file. Every scan helper defined here must
    be reached by a plant test here (the sweeps skip this file by name, so
    this is the only place that holds it to the rule), and no test body here
    may itself be an inline scan. A meta-scan that exempted itself would be
    the one unplanted scan in the suite."""
    source = Path(__file__).read_text(encoding="utf-8")
    assert _scan_helpers(source), "this file is expected to define scan helpers"
    assert _unplanted_scan_helpers(source) == [], (
        "a helper in the meta-scan that no plant test here reaches"
    )
    assert _inline_scan_tests(source, _global_scan_helper_names()) == []
