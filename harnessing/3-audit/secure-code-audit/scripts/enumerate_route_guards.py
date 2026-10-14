#!/usr/bin/env python3
"""Route×guard matrix enumerator (structural-lane pre-scan, Phase B2/D2).

Enumerates a checkout's HTTP route registrations and the authentication/
authorization guards actually applied to each, emitting the route×guard
matrix as a judged worklist — the enforcement-asymmetry class (one route
in a family guarded, its sibling not) was ~80% false-negative for
narrative review lanes (awx-false-negative-analysis: 4 of 5 missed highs;
deep-fn-technique-plan §1.3). Narrative lanes sample routes; an
enumerated matrix makes "which registrations lack the guard their
siblings carry" a mechanical question the model then judges.

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md). An unguarded row is not a
finding: the route may be intentionally public, guarded at the gateway,
or dead. The judging protocol lives in secure-code-audit SKILL.md
(route×guard pre-scan section) — and the lane may NOT close with
unjudged rows: the un-judged remainder is a coverage_gap, not silence.

Framework families:
  go-http     net/http HandleFunc/Handle, gorilla-mux
              HandleFunc/Handle(+.Methods), chi/echo/gin-style verb
              registrations (Get/GET/Post/POST/...), plus receiver-scoped
              `.Use(mw)` middleware and guard-wrapped handler expressions.
  django-drf  urls.py path()/re_path()/url() registrations; class-based
              views' permission_classes/authentication_classes;
              @login_required/@permission_required/@api_view decorators;
              REST_FRAMEWORK DEFAULT_PERMISSION_CLASSES baseline;
              AllowAny as an explicit unguard marker.
  flask       AST-based (target code is parsed, never imported):
              @<app|blueprint>.route / verb decorators (.get/.post/...),
              add_url_rule() incl. MethodView/View .as_view() classes (one
              row per HTTP method the class defines), Flask-RESTful /
              flask-restx add_resource() and @<api|namespace>.route
              resource classes. Guards: handler/method decorators, class
              `decorators` / `method_decorators` (inherited through
              in-repo base classes), and before_request /
              before_app_request handlers that can reject a request
              (abort/raise/return) as receiver- or app-wide baselines.
              Explicit public/exempt decorators are unguard markers.
              Asymmetry is judged per file AND per guard family: a guard
              family (scope, admin, role, permission, token, authn, csrf)
              carried by most rows of a view class / receiver but missing
              from a minority flags that minority.

Other web frameworks detected in the tree (express, fastapi, spring) are
emitted as coverage_gaps so the audit's negative_results can name what
this enumerator did not cover; flask imports with no enumerable route
registration are a coverage_gap too (unrecognized registration shape).

Guard recognition is NAME-BASED and deliberately over-inclusive
(anything matching auth/rbac/token/permission/... shapes counts as a
guard); the judge decides whether a recognized guard actually enforces.
Symbol-index enrichment: when a per-run index exists
(`traust build symbol-index`), handler definitions are resolved to
file:line through it; without one, the registration site is the anchor.

Usage:
    python3 enumerate_route_guards.py <repo-path> [--out <file>]
                                      [--index <symbols.db>]

Output defaults to <repo-basename>-route-guards.json in the CWD.
Exit 0 on a completed enumeration (gaps included); 1 on bad input.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import json
import re
import sqlite3
import sys
from pathlib import Path

from traust.paths import HARNESS_ROOT

GUARD_RX = re.compile(
    r"(?i)(auth[nz]?|authenticate|authoriz|login|rbac|permission|"
    r"require|protect|verify|token|jwt|oidc|oauth|session|csrf|"
    r"admin[_A-Z]|acl|scope|role|guard|secure)"
)

# names that look like guards but explicitly DISABLE guarding — these mark
# a row as judgement-required even when other "guards" match
UNGUARD_RX = re.compile(
    r"(?i)(allowany|allow_any|anonymous|skipauth|skip_auth|noauth|"
    r"no_auth|unauthenticated|public|insecureskip)"
)

SKIP_DIRS = {
    ".git",
    "vendor",
    "node_modules",
    "third_party",
    "testdata",
    ".tox",
    "__pycache__",
    "dist",
    "build",
    ".venv",
    "venv",
}
TEST_NAME_RX = re.compile(r"(^|[._-])(test|spec|mock|fixture)s?([._-]|$)")
MAX_FILE_BYTES = 2 * 1024 * 1024

GO_VERBS = (
    "Get",
    "Post",
    "Put",
    "Delete",
    "Patch",
    "Head",
    "Options",
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
)

GO_HANDLEFUNC_RX = re.compile(
    r"(?P<recv>[\w.]+)\.(?P<method>HandleFunc|Handle)\(\s*"
    r'"(?P<pattern>[^"]+)"\s*,\s*(?P<handler>[^)]+?)\s*\)'
)
GO_VERB_RX = re.compile(
    r"(?P<recv>[\w.]+)\.(?P<method>" + "|".join(GO_VERBS) + r")\(\s*"
    r'"(?P<pattern>[^"]+)"\s*,\s*(?P<handler>[^)]+?)\s*\)'
)
GO_USE_RX = re.compile(r"(?P<recv>[\w.]+)\.Use\(\s*(?P<mws>[^)]+?)\s*\)")

PY_URL_RX = re.compile(
    r'(?:path|re_path|url)\(\s*r?["\'](?P<pattern>[^"\']*)["\']\s*,\s*'
    r"(?P<view>[\w.]+(?:\.as_view\(\))?)"
)
PY_PERM_RX = re.compile(r"permission_classes\s*=\s*[\[\(](?P<perms>[^\]\)]*)[\]\)]")
PY_DECOR_RX = re.compile(r"^\s*@(?P<name>[\w.]+)", re.M)

OTHER_FRAMEWORKS = [
    (
        "express",
        re.compile(
            r'\brequire\(["\']express["\']\)|'
            r'from\s+["\']express["\']'
        ),
    ),
    ("fastapi", re.compile(r"\bfrom fastapi import|\bFastAPI\(")),
    ("spring", re.compile(r"@(RestController|RequestMapping|GetMapping)")),
]

FLASK_IMPORT_RX = re.compile(
    r"^\s*(?:from\s+(?:flask|flask_restful|flask_restx|flask_restplus|flask_smorest)\b"
    r"|import\s+(?:flask|flask_restful|flask_restx|flask_restplus|flask_smorest)\b)",
    re.M,
)
FASTAPI_IMPORT_RX = re.compile(r"^\s*(?:from\s+fastapi\b|import\s+fastapi\b)", re.M)


def _walk(repo: Path, suffixes: tuple[str, ...]):
    for p in sorted(repo.rglob("*")):
        if not p.is_file() or p.is_symlink() or p.suffix not in suffixes:
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(repo).parts):
            continue
        if TEST_NAME_RX.search(p.name.lower()):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _guards_in(expr: str) -> list[str]:
    """Names inside an expression that look like guards (dedup, ordered)."""
    out, seen = [], set()
    for tok in re.findall(r"[A-Za-z_][\w.]*", expr):
        if GUARD_RX.search(tok) and not UNGUARD_RX.search(tok) and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def _unguards_in(expr: str) -> list[str]:
    return sorted({t for t in re.findall(r"[A-Za-z_][\w.]*", expr) if UNGUARD_RX.search(t)})


def make_row(family, method, pattern, handler, path, line, guards, scope_guards, unguards):
    all_guards = list(dict.fromkeys(guards + scope_guards))
    row = {
        "family": family,
        "method": method,
        "pattern": pattern,
        "handler": {"expr": handler[:200], "path": path, "line": line},
        "guards": guards,
        "scope_guards": scope_guards,
        "registration": {"path": path, "line": line},
        "judgement_required": not all_guards or bool(unguards),
    }
    if unguards:
        row["unguard_markers"] = unguards
    return row


# --------------------------------------------------------------------------
# family: go-http
# --------------------------------------------------------------------------


def enumerate_go(repo: Path, rows: list):
    for f in _walk(repo, (".go",)):
        text = _read(f)
        if (
            ".HandleFunc(" not in text
            and ".Handle(" not in text
            and not any(f".{v}(" in text for v in GO_VERBS)
        ):
            continue
        rel = str(f.relative_to(repo))
        # receiver-scoped middleware: r.Use(authMW) anywhere in the file
        # applies to that receiver's registrations (over-approximation —
        # the judge sees scope_guards separately from direct guards)
        scope: dict[str, list[str]] = {}
        unguard_scope: dict[str, list[str]] = {}
        for m in GO_USE_RX.finditer(text):
            recv = m.group("recv")
            scope.setdefault(recv, []).extend(_guards_in(m.group("mws")))
            unguard_scope.setdefault(recv, []).extend(_unguards_in(m.group("mws")))
        for rx in (GO_HANDLEFUNC_RX, GO_VERB_RX):
            for m in rx.finditer(text):
                recv = m.group("recv")
                if recv in ("t", "b", "suite"):  # test receivers
                    continue
                handler = m.group("handler")
                line = text[: m.start()].count("\n") + 1
                rows.append(
                    make_row(
                        "go-http",
                        m.group("method"),
                        m.group("pattern"),
                        handler,
                        rel,
                        line,
                        guards=_guards_in(handler),
                        scope_guards=list(dict.fromkeys(scope.get(recv, []))),
                        unguards=_unguards_in(handler) + unguard_scope.get(recv, []),
                    )
                )


# --------------------------------------------------------------------------
# family: django-drf
# --------------------------------------------------------------------------


def _view_guard_index(repo: Path) -> dict[str, dict]:
    """Map view/class name -> guards from its definition site."""
    idx: dict[str, dict] = {}
    for f in _walk(repo, (".py",)):
        text = _read(f)
        rel = str(f.relative_to(repo))
        for m in re.finditer(r"^class\s+(?P<name>\w+)\s*\((?P<bases>[^)]*)\)\s*:", text, re.M):
            body_start = m.end()
            nxt = re.search(r"^\S", text[body_start:], re.M)
            body = text[body_start : body_start + nxt.start()] if nxt else text[body_start:]
            perms = PY_PERM_RX.search(body)
            guards = _guards_in(perms.group("perms")) if perms else []
            unguards = _unguards_in(perms.group("perms")) if perms else []
            idx[m.group("name")] = {
                "guards": guards,
                "unguards": unguards,
                "path": rel,
                "line": text[: m.start()].count("\n") + 1,
                "has_perm_attr": bool(perms),
            }
        for m in re.finditer(
            r"(?P<decos>(?:^\s*@[\w.()'\", =\[\]]+\n)+)"
            r"^\s*def\s+(?P<name>\w+)\s*\(",
            text,
            re.M,
        ):
            decos = m.group("decos")
            guards = _guards_in(decos)
            unguards = _unguards_in(decos)
            if guards or unguards:
                idx[m.group("name")] = {
                    "guards": guards,
                    "unguards": unguards,
                    "path": rel,
                    "line": text[: m.start()].count("\n") + 1,
                    "has_perm_attr": True,
                }
    return idx


def _drf_default_guards(repo: Path) -> list[str]:
    for f in _walk(repo, (".py",)):
        if "settings" not in f.name.lower() and "settings" not in str(f.parent).lower():
            continue
        text = _read(f)
        m = re.search(r"DEFAULT_PERMISSION_CLASSES.*?[\[\(](?P<perms>[^\]\)]*)[\]\)]", text, re.S)
        if m:
            return _guards_in(m.group("perms"))
    return []


def enumerate_django(repo: Path, rows: list):
    url_files = [f for f in _walk(repo, (".py",)) if "url" in f.name.lower()]
    if not url_files:
        return
    view_idx = _view_guard_index(repo)
    defaults = _drf_default_guards(repo)
    for f in url_files:
        text = _read(f)
        rel = str(f.relative_to(repo))
        for m in PY_URL_RX.finditer(text):
            view = m.group("view")
            base = view.split(".")[0].replace(".as_view()", "")
            info = (
                view_idx.get(base)
                or view_idx.get(view.replace(".as_view()", "").split(".")[-1])
                or {}
            )
            line = text[: m.start()].count("\n") + 1
            rows.append(
                make_row(
                    "django-drf",
                    "any",
                    m.group("pattern") or "/",
                    view,
                    info.get("path", rel),
                    info.get("line", line),
                    guards=info.get("guards", []),
                    scope_guards=[] if info.get("has_perm_attr") else defaults,
                    unguards=info.get("unguards", []),
                )
            )


# --------------------------------------------------------------------------
# family: flask (AST — target code is parsed, never imported)
# --------------------------------------------------------------------------

FLASK_RECEIVER_CTORS = {
    "Flask": "app",
    "Blueprint": "blueprint",
    "Api": "api",
    "Namespace": "namespace",
}
FLASK_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
FLASK_REGISTRATION_ATTRS = {"route", "add_url_rule", "add_resource", *FLASK_VERBS}
VIEW_BASE_RX = re.compile(r"(MethodView|^View$|\.View$|Resource$|MethodResource$)")
# flask-local additions to the shared shapes: `check_*` decorators guard,
# `*exempt*` decorators (csrf.exempt, auth-exempt markers) unguard
FLASK_GUARD_EXTRA_RX = re.compile(r"(?i)(^|\.)check_")
FLASK_UNGUARD_EXTRA_RX = re.compile(r"(?i)exempt")
GUARD_FAMILIES = (
    ("scope", re.compile(r"(?i)scope")),
    ("admin", re.compile(r"(?i)admin")),
    ("role", re.compile(r"(?i)(role|rbac|acl)")),
    ("permission", re.compile(r"(?i)permission")),
    ("csrf", re.compile(r"(?i)csrf")),
    ("token", re.compile(r"(?i)(jwt|token|oauth|oidc)")),
    ("authn", re.compile(r"(?i)(login|auth|session)")),
)


def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _const_str(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _str_list(node) -> list[str]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [s for s in (_const_str(e) for e in node.elts) if s is not None]
    return []


def _kwarg(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _flask_split(names: list[str]) -> tuple[list[str], list[str]]:
    """Name-based guard/unguard split for decorator-ish names, using the
    shared GUARD/UNGUARD shapes plus the flask-local extras."""
    guards, unguards = [], []
    for n in names:
        if not n:
            continue
        last = n.split(".")[-1]
        if last in FLASK_REGISTRATION_ATTRS:
            continue
        if UNGUARD_RX.search(n) or FLASK_UNGUARD_EXTRA_RX.search(n):
            unguards.append(n)
        elif GUARD_RX.search(n) or FLASK_GUARD_EXTRA_RX.search(n):
            guards.append(n)
    return list(dict.fromkeys(guards)), sorted(set(unguards))


def _names_in(node) -> list[str]:
    """Dotted names of the elements of a decorators-style expression:
    a list/tuple of decorators, or a dict of verb -> list (method_decorators)."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [_dotted(e) for e in node.elts]
    if isinstance(node, ast.Dict):
        out = []
        for v in node.values:
            out.extend(_names_in(v))
        return out
    return []


def _method_decorators(node) -> tuple[list[str], dict[str, list[str]]]:
    """(applies-to-all, per-verb) from a `method_decorators = ...` value."""
    if isinstance(node, ast.Dict):
        per: dict[str, list[str]] = {}
        for k, v in zip(node.keys, node.values, strict=False):
            key = _const_str(k) if k is not None else None
            if key:
                per[key.lower()] = _names_in(v)
        return [], per
    return _names_in(node), {}


def _can_reject(fn: ast.AST) -> bool:
    """A before_request hook counts as a guard only if it can end the
    request: it raises, calls abort(), or returns a value."""
    for n in ast.walk(fn):
        if isinstance(n, ast.Raise):
            return True
        if isinstance(n, ast.Return) and n.value is not None:
            return True
        if isinstance(n, ast.Call) and _dotted(n.func).split(".")[-1] == "abort":
            return True
    return False


def _mentions_guard(fn: ast.AST, name: str) -> bool:
    if GUARD_RX.search(name) or FLASK_GUARD_EXTRA_RX.search(name):
        return True
    for n in ast.walk(fn):
        if isinstance(n, (ast.Name, ast.Attribute)) and GUARD_RX.search(_dotted(n)):
            return True
    return False


def _flask_files(repo: Path) -> list[tuple[Path, str, ast.Module]]:
    out = []
    for f in _walk(repo, (".py",)):
        text = _read(f)
        if not text or (
            "route" not in text
            and "add_url_rule" not in text
            and "add_resource" not in text
            and "before_request" not in text
            and "before_app_request" not in text
            and "Blueprint" not in text
            and "Flask" not in text
            and "Namespace" not in text
            and "View" not in text
            and "Resource" not in text
        ):
            continue
        try:
            tree = ast.parse(text, filename=str(f))
        except (SyntaxError, ValueError):
            continue
        out.append((f, text, tree))
    return out


CONST_RX = re.compile(
    r"^(?P<name>[A-Z_][A-Z0-9_]*)\s*(?::\s*str\s*)?=\s*[\"'](?P<val>[^\"'\n]*)[\"']\s*$", re.M
)
TEST_DIR_PARTS = {"tests", "test", "testing", "fixtures", "examples", "example"}


def _string_constants(repo: Path) -> dict[str, str]:
    """Module-level UPPER_CASE string constants anywhere in the tree, so a
    route registered as `rule=SOME_PATH` resolves to its literal path."""
    consts: dict[str, str] = {}
    for f in _walk(repo, (".py",)):
        for m in CONST_RX.finditer(_read(f)):
            consts.setdefault(m.group("name"), m.group("val"))
    return consts


def _pattern(node, consts: dict) -> tuple[str | None, bool]:
    """(pattern, dynamic). Literal or resolvable constant -> the path; any
    other expression -> its source text, flagged dynamic. A registration is
    never dropped because its path is computed."""
    if node is None:
        return None, False
    s = _const_str(node)
    if s is not None:
        return s, False
    if isinstance(node, ast.Name) and node.id in consts:
        return consts[node.id], False
    try:
        return ast.unparse(node)[:160], True
    except (AttributeError, ValueError, RecursionError):
        return "<dynamic>", True


def _flask_index(repo: Path, files):
    """Repo-wide index: flask receivers, functions, view classes,
    before_request hooks and blueprint registrations. Receivers come only
    from files that import a flask-family module, so same-named objects of
    other frameworks are not mistaken for flask apps."""
    receivers: dict[str, str] = {}
    functions: dict[str, list[dict]] = {}
    classes: dict[str, dict] = {}
    hooks: list[dict] = []  # {recv, fname, app_hook, path, node}
    pending: list[dict] = []
    registered: dict[str, set[str]] = {}  # file -> blueprint names registered there
    imported: dict[str, dict[str, str]] = {}  # file -> local name -> source module

    for f, text, tree in files:
        rel = str(f.relative_to(repo))
        imports_flask = bool(FLASK_IMPORT_RX.search(text))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = _resolve_import(rel, node.module, node.level)
                for alias in node.names:
                    imported.setdefault(rel, {})[alias.asname or alias.name] = mod
            if imports_flask and isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                ctor = _dotted(node.value.func).split(".")[-1]
                kind = FLASK_RECEIVER_CTORS.get(ctor) or (
                    "namespace" if ctor == "namespace" else None
                )
                if kind:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            receivers[t.id] = kind
                        elif isinstance(t, ast.Attribute):
                            receivers[t.attr] = kind
            if not isinstance(node, ast.Call):
                continue
            fn = _dotted(node.func)
            last = fn.split(".")[-1]
            if last == "register_blueprint" and node.args:
                registered.setdefault(rel, set()).add(_dotted(node.args[0]).split(".")[-1])
            if last in ("before_request", "before_app_request") and node.args and "." in fn:
                hook = _dotted(node.args[0]).split(".")[-1]
                if hook:
                    pending.append(
                        {
                            "recv": fn.rsplit(".", 1)[0].split(".")[-1],
                            "fname": hook,
                            "app_hook": last == "before_app_request",
                            "path": rel,
                        }
                    )
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decos = [_dotted(d) for d in node.decorator_list]
                functions.setdefault(node.name, []).append(
                    {"path": rel, "line": node.lineno, "decos": decos, "node": node}
                )
                for d in decos:
                    last = d.split(".")[-1]
                    if last in ("before_request", "before_app_request") and "." in d:
                        hooks.append(
                            {
                                "recv": d.rsplit(".", 1)[0].split(".")[-1],
                                "fname": node.name,
                                "app_hook": last == "before_app_request",
                                "path": rel,
                                "node": node,
                            }
                        )
            elif isinstance(node, ast.ClassDef):
                bases = [_dotted(b) for b in node.bases]
                info = {
                    "path": rel,
                    "line": node.lineno,
                    "bases": bases,
                    "class_decos": [_dotted(d) for d in node.decorator_list],
                    "decorators": [],
                    "method_all": [],
                    "method_per": {},
                    "methods": {},
                    "view_like": any(VIEW_BASE_RX.search(b) for b in bases),
                }
                for stmt in node.body:
                    if isinstance(stmt, ast.Assign):
                        for t in stmt.targets:
                            if not isinstance(t, ast.Name):
                                continue
                            if t.id == "decorators":
                                info["decorators"] = _names_in(stmt.value)
                            elif t.id == "method_decorators":
                                info["method_all"], info["method_per"] = _method_decorators(
                                    stmt.value
                                )
                    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                        stmt.name in FLASK_VERBS or stmt.name == "dispatch_request"
                    ):
                        info["methods"][stmt.name] = {
                            "line": stmt.lineno,
                            "decos": [_dotted(d) for d in stmt.decorator_list],
                        }
                classes[node.name] = info

    for p in pending:
        fn = _resolve_fn(p["fname"], functions, p["path"])
        if fn:
            hooks.append({**p, "node": fn["node"]})

    guard_hooks = []
    for h in hooks:
        if _can_reject(h["node"]) and _mentions_guard(h["node"], h["fname"]):
            h["label"] = f"before_request:{h['fname']}"
            h["app_level"] = h["app_hook"] or receivers.get(h["recv"]) == "app"
            guard_hooks.append(h)
    return (
        receivers,
        functions,
        classes,
        {"hooks": guard_hooks, "registered": registered, "imported": imported},
    )


def _module_of(rel: str) -> str:
    mod = rel[:-3] if rel.endswith(".py") else rel
    if mod.endswith("/__init__"):
        mod = mod[: -len("/__init__")]
    return mod.replace("/", ".")


def _resolve_import(rel: str, module: str | None, level: int) -> str:
    """Dotted source module of a `from ... import` in file `rel` (relative
    imports resolved against the file's package)."""
    if not level:
        return module or ""
    pkg = _module_of(rel).split(".")
    if not rel.endswith("__init__.py"):
        pkg = pkg[:-1]
    pkg = pkg[: len(pkg) - (level - 1)] if level > 1 else pkg
    return ".".join([*pkg, module] if module else pkg)


def _same_module(rel: str, module: str) -> bool:
    """True when `module` names the file `rel` (suffix match, so a src/
    layout or a repo-root prefix does not defeat the comparison)."""
    if not module:
        return False
    mod = _module_of(rel)
    return mod == module or mod.endswith("." + module)


def _baseline_for(receiver: str | None, reg_path: str, base: dict) -> list[str]:
    """before_request labels that apply to a route registered on `receiver`
    in `reg_path`. A blueprint hook covers that blueprint's routes. An app
    hook covers routes on the same app object: in the hook's own file, in
    the module the hook's file imports that app object from (the factory /
    plug-in pattern), and on every blueprint the hook's file registers —
    never every flask route in the tree (one repo can hold several
    unrelated apps)."""
    out = []
    for h in base["hooks"]:
        if not h["app_level"]:
            if receiver and receiver == h["recv"]:
                out.append(h["label"])
            continue
        same_app = receiver == h["recv"] and (
            reg_path == h["path"]
            or _same_module(reg_path, base["imported"].get(h["path"], {}).get(h["recv"], ""))
        )
        if same_app or (receiver and receiver in base["registered"].get(h["path"], set())):
            out.append(h["label"])
    return list(dict.fromkeys(out))


def _class_chain(name: str, classes: dict, seen=None) -> list[dict]:
    """The class and its in-repo bases (nearest first), cycle-safe."""
    seen = seen or set()
    info = classes.get(name)
    if info is None or name in seen:
        return []
    seen.add(name)
    chain = [info]
    for b in info["bases"]:
        chain.extend(_class_chain(b.split(".")[-1], classes, seen))
    return chain


def _is_view_class(name: str, classes: dict) -> bool:
    return any(c["view_like"] or c["methods"] for c in _class_chain(name, classes))


def _mark(row: dict, receiver, dynamic: bool, reg_path: str) -> dict:
    if receiver:
        row["receiver"] = receiver
    if dynamic:
        row["pattern_dynamic"] = True
    if any(part in TEST_DIR_PARTS for part in Path(reg_path).parts[:-1]):
        row["test_path"] = True
    return row


def _class_rows(cls_name, patterns, receiver, reg_path, reg_line, classes, base, rows):
    chain = _class_chain(cls_name, classes)
    if not chain:
        return
    methods: dict[str, dict] = {}
    for c in reversed(chain):  # nearest definition wins
        methods.update(c["methods"])
    class_level = []
    per_verb: dict[str, list[str]] = {}
    for c in chain:
        class_level += c["class_decos"] + c["decorators"] + c["method_all"]
        for verb, names in c["method_per"].items():
            per_verb.setdefault(verb, []).extend(names)
    cls_guards, cls_unguards = _flask_split(class_level)
    base_guards = _baseline_for(receiver, reg_path, base)
    verbs = [v for v in methods if v != "dispatch_request"] or (
        ["dispatch_request"] if "dispatch_request" in methods else []
    )
    for verb in verbs:
        m = methods[verb]
        guards, unguards = _flask_split(m["decos"])
        pv_guards, pv_unguards = _flask_split(per_verb.get(verb, []))
        method = "ANY" if verb == "dispatch_request" else verb.upper()
        for pattern, dynamic in patterns:
            row = make_row(
                "flask",
                method,
                pattern,
                f"{cls_name}.{verb}",
                reg_path,
                reg_line,
                guards=guards,
                scope_guards=list(dict.fromkeys(pv_guards + cls_guards + base_guards)),
                unguards=sorted(set(unguards + pv_unguards + cls_unguards)),
            )
            owner = next((c for c in chain if verb in c["methods"]), chain[0])
            row["handler"]["path"] = owner["path"]
            row["handler"]["line"] = m["line"]
            row["view_class"] = cls_name
            rows.append(_mark(row, receiver, dynamic, reg_path))


def _function_row(fn_name, fn_info, pattern, dynamic, methods, receiver, reg_path, reg_line, base):
    guards, unguards = _flask_split(fn_info.get("decos", []) if fn_info else [])
    row = make_row(
        "flask",
        ",".join(methods) if methods else "GET",
        pattern,
        fn_name,
        reg_path,
        reg_line,
        guards=guards,
        scope_guards=_baseline_for(receiver, reg_path, base),
        unguards=unguards,
    )
    if fn_info:
        row["handler"]["path"] = fn_info["path"]
        row["handler"]["line"] = fn_info["line"]
    return _mark(row, receiver, dynamic, reg_path)


def _resolve_fn(name: str, functions: dict, rel: str) -> dict | None:
    cands = functions.get(name.split(".")[-1], [])
    return next((c for c in cands if c["path"] == rel), cands[0] if cands else None)


def _view_target(view) -> tuple[str, list[str]]:
    """(handler name, names wrapped around it at registration time) for a
    view_func expression: `f`, `guard(f)`, `lambda: f(...)`, `mod.f`."""
    if isinstance(view, ast.Lambda):
        body = view.body
        return (_dotted(body.func) if isinstance(body, ast.Call) else _dotted(body)), []
    if isinstance(view, ast.Call) and view.args:
        inner, wraps = _view_target(view.args[0])
        return inner, [_dotted(view.func), *wraps]
    return _dotted(view), []


def enumerate_flask(repo: Path, rows: list) -> bool:
    """Returns True when the tree uses a flask-family framework (so an
    empty result can be reported as a coverage gap, never as clean)."""
    files = _flask_files(repo)
    uses_flask = any(FLASK_IMPORT_RX.search(text) for _f, text, _t in files)
    if not uses_flask:
        return False
    receivers, functions, classes, base = _flask_index(repo, files)
    consts = _string_constants(repo)

    for f, text, tree in files:
        rel = str(f.relative_to(repo))
        imports_flask = bool(FLASK_IMPORT_RX.search(text))
        # a file that also uses fastapi: verb decorators are ambiguous there
        # (both frameworks spell them `@app.get`), so only route /
        # add_url_rule / add_resource on receivers known to be flask objects
        # count, and any name this file binds to a non-flask constructor
        # (FastAPI(), APIRouter(), a FastAPI subclass) shadows the global one
        mixed = bool(FASTAPI_IMPORT_RX.search(text))
        other = {
            t.id
            for n in ast.walk(tree)
            if mixed and isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
            if _dotted(n.value.func).split(".")[-1] not in FLASK_RECEIVER_CTORS
            for t in n.targets
            if isinstance(t, ast.Name)
        }

        def _flask_receiver(
            dotted: str, imports_flask=imports_flask, mixed=mixed, other=other
        ) -> str | None:
            if "." not in dotted:
                return None
            recv = dotted.rsplit(".", 1)[0].split(".")[-1]
            if recv in other:
                return None
            if mixed:
                return recv if recv in receivers else None
            return recv if (recv in receivers or imports_flask) else None

        for node in ast.walk(tree):
            # decorator registrations on functions and classes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for d in node.decorator_list:
                    if not isinstance(d, ast.Call):
                        continue
                    dn = _dotted(d.func)
                    attr = dn.split(".")[-1]
                    recv = _flask_receiver(dn)
                    if recv is None or attr not in ("route", *FLASK_VERBS):
                        continue
                    if attr != "route" and (mixed or recv not in receivers):
                        continue  # verb decorators only on known flask receivers
                    pattern, dynamic = _pattern(d.args[0] if d.args else _kwarg(d, "rule"), consts)
                    if pattern is None:
                        continue
                    if isinstance(node, ast.ClassDef):
                        _class_rows(
                            node.name,
                            [(pattern, dynamic)],
                            recv,
                            rel,
                            d.lineno,
                            classes,
                            base,
                            rows,
                        )
                        continue
                    methods = (
                        [attr.upper()]
                        if attr != "route"
                        else [m.upper() for m in _str_list(_kwarg(d, "methods"))]
                    )
                    info = {
                        "path": rel,
                        "line": node.lineno,
                        "decos": [_dotted(x) for x in node.decorator_list],
                    }
                    rows.append(
                        _function_row(
                            node.name, info, pattern, dynamic, methods, recv, rel, d.lineno, base
                        )
                    )
            # call registrations
            if not isinstance(node, ast.Call):
                continue
            fn = _dotted(node.func)
            attr = fn.split(".")[-1]
            if attr not in ("add_url_rule", "add_resource"):
                continue
            recv = _flask_receiver(fn)
            if recv is None:
                continue
            line = node.lineno
            if attr == "add_resource":
                if not node.args:
                    continue
                cls = _dotted(node.args[0]).split(".")[-1]
                patterns = [p for p in (_pattern(a, consts) for a in node.args[1:]) if p[0]]
                if cls and patterns and cls in classes:
                    _class_rows(cls, patterns, recv, rel, line, classes, base, rows)
                continue
            pattern, dynamic = _pattern(node.args[0] if node.args else _kwarg(node, "rule"), consts)
            if pattern is None:
                continue
            view = _kwarg(node, "view_func")
            if view is None and len(node.args) >= 3:
                view = node.args[2]
            if view is None:
                continue
            if (
                isinstance(view, ast.Call)
                and isinstance(view.func, ast.Attribute)
                and view.func.attr == "as_view"
            ):
                cls = _dotted(view.func.value).split(".")[-1]
                if _is_view_class(cls, classes):
                    _class_rows(cls, [(pattern, dynamic)], recv, rel, line, classes, base, rows)
                continue
            target, wraps = _view_target(view)
            info = _resolve_fn(target, functions, rel) if target else None
            methods = [m.upper() for m in _str_list(_kwarg(node, "methods"))]
            row = _function_row(
                target or "<view>", info, pattern, dynamic, methods, recv, rel, line, base
            )
            wrap_guards, wrap_unguards = _flask_split(wraps)
            if wrap_guards or wrap_unguards:
                row["guards"] = list(dict.fromkeys(wrap_guards + row["guards"]))
                markers = sorted(set(wrap_unguards + row.get("unguard_markers", [])))
                if markers:
                    row["unguard_markers"] = markers
                row["judgement_required"] = not (row["guards"] or row["scope_guards"]) or bool(
                    markers
                )
            rows.append(row)
    return True


# --------------------------------------------------------------------------
# asymmetry grouping + symbol-index enrichment + gaps
# --------------------------------------------------------------------------


def find_asymmetries(rows: list) -> list:
    """Groups (same file, same family) where guard coverage differs —
    the AWX miss shape: one registration wrapped, its sibling bare."""
    groups: dict[tuple, list] = {}
    for r in rows:
        if r["family"] == "flask":
            continue  # judged by flask_asymmetries (per-method labels + guard families)
        groups.setdefault((r["family"], r["registration"]["path"]), []).append(r)
    out = []
    for (family, path), members in sorted(groups.items()):
        guarded = [r for r in members if r["guards"] or r["scope_guards"]]
        bare = [r for r in members if not r["guards"] and not r["scope_guards"]]
        if guarded and bare:
            out.append(
                {
                    "family": family,
                    "path": path,
                    "guarded": [r["pattern"] for r in guarded],
                    "unguarded": [r["pattern"] for r in bare],
                }
            )
            for r in bare:
                r["judgement_required"] = True
                r["asymmetry"] = True
    return out


def _guard_families(row: dict) -> set[str]:
    fams = set()
    for g in row["guards"] + row["scope_guards"]:
        for fam, rx in GUARD_FAMILIES:
            if rx.search(g):
                fams.add(fam)
                break
    return fams


def flask_asymmetries(rows: list) -> list:
    """Flask asymmetry groups. Two shapes, both marking the odd rows
    judgement_required:

    1. per registration file — some rows guarded, some bare (the same
       rule find_asymmetries applies to the other families; labels carry
       the HTTP method because class-based views share one pattern);
    2. per guard family within one view class or receiver — a family
       (scope, admin, role, permission, csrf, token, authn) that a strict
       majority of the group's rows carry, missing from guarded rows that
       lack it. That is the "every neighbour performs this check but this
       one" shape among rows that all carry SOME guard (bare rows are
       already reported by shape 1)."""
    frows = [r for r in rows if r["family"] == "flask"]
    out = []

    def label(r):
        return f"{r['method']} {r['pattern']}"

    by_file: dict[str, list] = {}
    for r in frows:
        by_file.setdefault(r["registration"]["path"], []).append(r)
    for path, members in sorted(by_file.items()):
        guarded = [r for r in members if r["guards"] or r["scope_guards"]]
        bare = [r for r in members if not r["guards"] and not r["scope_guards"]]
        if guarded and bare:
            out.append(
                {
                    "family": "flask",
                    "path": path,
                    "guarded": [label(r) for r in guarded],
                    "unguarded": [label(r) for r in bare],
                }
            )
            for r in bare:
                r["judgement_required"] = True
                r["asymmetry"] = True

    by_group: dict[tuple, list] = {}
    for r in frows:
        key = r.get("view_class") or r.get("receiver") or ""
        by_group.setdefault((r["registration"]["path"], key), []).append(r)
    for (path, key), members in sorted(by_group.items()):
        if len(members) < 2:
            continue
        fams = [_guard_families(r) for r in members]
        for fam, _rx in GUARD_FAMILIES:
            have = [r for r, fs in zip(members, fams, strict=True) if fam in fs]
            # bare rows are shape 1's business; this shape is about rows that
            # carry SOME guard but not the one their neighbours carry
            lack = [
                r
                for r, fs in zip(members, fams, strict=True)
                if fam not in fs and (r["guards"] or r["scope_guards"])
            ]
            if not have or not lack or len(have) <= len(lack):
                continue
            out.append(
                {
                    "family": "flask",
                    "path": path,
                    "group": key,
                    "guard_family": fam,
                    "guarded": [label(r) for r in have],
                    "unguarded": [label(r) for r in lack],
                }
            )
            for r in lack:
                r["judgement_required"] = True
                r["asymmetry"] = True
                gaps = r.setdefault("guard_family_gaps", [])
                if fam not in gaps:
                    gaps.append(fam)
    return out


def enrich_from_index(rows: list, index_db: Path):
    try:
        con = sqlite3.connect(f"file:{index_db}?mode=ro", uri=True)
    except sqlite3.Error:
        return
    try:
        for r in rows:
            name = re.sub(r"\(.*$", "", r["handler"]["expr"]).split(".")[-1]
            if not re.match(r"^\w+$", name):
                continue
            try:
                hit = con.execute(
                    "SELECT path, line FROM symbols WHERE name = ? "
                    "AND kind IN ('func', 'function', 'method') LIMIT 1",
                    (name,),
                ).fetchone()
            except sqlite3.Error:
                return
            if hit:
                r["handler"]["resolved"] = {"path": hit[0], "line": hit[1]}
    finally:
        con.close()


def detect_other_frameworks(repo: Path, gaps: list):
    hits: dict[str, str] = {}
    for f in _walk(repo, (".js", ".ts", ".py", ".java", ".kt")):
        text = _read(f)
        for name, rx in OTHER_FRAMEWORKS:
            if name not in hits and rx.search(text):
                hits[name] = str(f.relative_to(repo))
    for name, path in sorted(hits.items()):
        gaps.append(
            {
                "system": name,
                "reason": f"{name} routes detected but this enumerator covers only "
                f"go-http, django-drf and flask — this family's route×guard "
                f"matrix is UNENUMERATED",
                "evidence": path,
            }
        )


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def enumerate_routes(repo: Path, index_db: Path | None = None) -> dict:
    rows: list[dict] = []
    gaps: list[dict] = []
    enumerate_go(repo, rows)
    enumerate_django(repo, rows)
    uses_flask = enumerate_flask(repo, rows)
    asym = find_asymmetries(rows) + flask_asymmetries(rows)
    if index_db and index_db.is_file():
        enrich_from_index(rows, index_db)
    detect_other_frameworks(repo, gaps)
    if uses_flask and not any(r["family"] == "flask" for r in rows):
        gaps.append(
            {
                "system": "flask",
                "reason": "flask imports detected but no route registration this "
                "enumerator recognizes (route/verb decorators, add_url_rule, "
                "add_resource) — the flask route×guard matrix is UNENUMERATED",
                "evidence": next(
                    (
                        str(f.relative_to(repo))
                        for f in _walk(repo, (".py",))
                        if FLASK_IMPORT_RX.search(_read(f))
                    ),
                    "",
                ),
            }
        )

    rows.sort(
        key=lambda r: (
            not r["judgement_required"],
            not r.get("asymmetry", False),
            r["registration"]["path"],
            r["registration"]["line"],
        )
    )
    by_family: dict[str, int] = {}
    for r in rows:
        by_family[r["family"]] = by_family.get(r["family"], 0) + 1
    return {
        "artifact": "route-guard-matrix",
        "repo": repo.name,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": (HARNESS_ROOT / "VERSION").read_text().strip()
        if (HARNESS_ROOT / "VERSION").is_file()
        else "unknown",
        "routes": rows,
        "asymmetries": asym,
        "coverage_gaps": gaps,
        "stats": {
            "total": len(rows),
            "judgement_required": sum(1 for r in rows if r["judgement_required"]),
            "asymmetry_rows": sum(1 for r in rows if r.get("asymmetry")),
            "by_family": by_family,
        },
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("repo", type=Path, help="local checkout to enumerate")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--index", type=Path, default=None, help="optional symbols.db from build_symbol_index.py"
    )
    args = ap.parse_args(argv)

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 1
    result = enumerate_routes(repo, args.index)
    out = args.out or Path(f"{repo.name}-route-guards.json")
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    s = result["stats"]
    print(
        f"{result['repo']}: {s['total']} routes "
        f"({s['judgement_required']} to judge, "
        f"{s['asymmetry_rows']} in asymmetry groups), "
        f"{len(result['asymmetries'])} asymmetry groups, "
        f"{len(result['coverage_gaps'])} coverage gaps -> {out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
