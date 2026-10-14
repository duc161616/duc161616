#!/usr/bin/env python3
"""Apply a Chinese -> English dictionary to ARTEX source, safely.

Replacement happens only on the *full contents of a string literal*, never on a
substring and never inside a comment. Partial replacement is what turns a
translation pass into a debugging session: a Chinese fragment swapped inside a
longer literal leaves mixed-language output, and a swap inside a comment is pure
churn that bloats the diff and hides the real changes.

Strings listed in PROTECTED are refused outright. They are sentinels other files
compare against (see TRANSLATION.md), so changing one here without changing
every consumer alters behaviour with no compile error to warn you.

    python3 bbkit/i18n_apply.py ARTEX dict.json --dry-run
    python3 bbkit/i18n_apply.py ARTEX dict.json
    python3 bbkit/i18n_apply.py ARTEX dict.json --layer ui
    python3 bbkit/i18n_apply.py ARTEX --coverage        # what is left to translate

The dictionary is {"<exact Chinese literal>": "<English>"}. Build it from the
catalogue that i18n_extract.py writes, so keys match literals exactly.
"""
import argparse
import json
import os
import re
import sys
from collections import Counter

CJK = re.compile(r'[一-鿿]')

# Sentinels: compared against elsewhere in the codebase. Never auto-replace.
PROTECTED = {
    '备案': 'ICP filing keyword matched in db/company_scope.go:160 — it is the concept, '
            'not a translatable label',
    '[模型]': 'model-decision sentinel read in intercept/intercept.go:481, '
              'db/intercept.go:251, db/task_archives_restore.go:680',
    '实际操作：': 'required reason prefix checked in intercept/prompt.go:193',
    '新对话': 'default-title sentinel compared in server/conversations.go:443',
    '命令': 'label compared in web/src/components/transcript.tsx:406',
}

# Go interpreted/raw strings and TS/JS strings, including template literals.
LITERAL = re.compile(
    r'"((?:[^"\\\n]|\\.)*)"'      # "..."
    r"|'((?:[^'\\\n]|\\.)*)'"     # '...'
    r'|`([^`]*)`',                # `...` (Go raw / JS template)
    re.S,
)
LINE_COMMENT = re.compile(r'//[^\n]*')
BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)

PROMPT_FILES = ('agent/promptcatalog.go', 'agent/planner.go', 'agent/worker.go',
                'agent/goals.go', 'agent/prompt.go', 'agent/mainagent.go',
                'agent/retester.go', 'intercept/prompt.go')
TOOLDESC_FILES = ('agent/tools.go', 'agent/tools_insert.go', 'agent/tools_digest.go',
                  'agent/toolcatalog.go')


def layer_of(rel):
    norm = rel.replace(os.sep, '/')
    if norm.endswith('_test.go') or '.test.' in norm or '/mock/' in norm:
        return 'test'
    if norm in PROMPT_FILES:
        return 'prompt'
    if norm in TOOLDESC_FILES:
        return 'tooldesc'
    if norm.startswith('web/'):
        return 'ui'
    return 'apimsg'


def comment_spans(text):
    """Byte ranges that are comments, so literals inside them are left alone."""
    spans = []
    for rx in (BLOCK_COMMENT, LINE_COMMENT):
        for m in rx.finditer(text):
            spans.append((m.start(), m.end()))
    return spans


def in_spans(pos, spans):
    return any(a <= pos < b for a, b in spans)


def source_files(root, layer=None):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('.git', 'node_modules', '.next', 'dist')]
        for fn in filenames:
            if not fn.endswith(('.go', '.ts', '.tsx')):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if layer and layer_of(rel) != layer:
                continue
            yield full, rel



def validate_literal_body(text, quote):
    """Check that text is a well-formed body for a literal of this quote type.

    Dictionary values are given in SOURCE form: exactly the characters that go
    between the quotes, with escape sequences already written as escapes (\\n for
    a newline, \\" for a quote inside a "..." literal). That contract matters
    because a value legitimately contains escapes — a tool description ending in
    \\n, a JSON example containing \\" — and auto-escaping here would double the
    backslashes and corrupt them.

    So this validates instead of transforming, and raises on anything that would
    not compile. A dry run then surfaces the problem, which is what a silent
    insert does not: inserting a bare quote into a "..." literal breaks the file
    and the dry run reports success.
    """
    if quote == '`':
        # A raw string has no escapes: any backtick ends it early.
        if '`' in text:
            raise ValueError(f'value contains a backtick, which closes a raw string '
                             f'literal early: {text[:60]!r}')
        return text

    if '\n' in text or '\r' in text:
        raise ValueError(f'value contains a real newline; write it as the two-character '
                         f'escape \\n instead: {text[:60]!r}')

    # Walk the string so an escaped quote is accepted and a bare one is not.
    i = 0
    while i < len(text):
        c = text[i]
        if c == '\\':
            if i + 1 >= len(text):
                raise ValueError(f'value ends in a lone backslash: {text[-40:]!r}')
            i += 2
            continue
        if c == quote:
            raise ValueError(f'value contains an unescaped {quote} inside a {quote}...{quote} '
                             f'literal; write it as \\{quote}: {text[:60]!r}')
        i += 1
    return text


def apply_file(path, table, dry_run):
    with open(path, encoding='utf-8') as fh:
        text = fh.read()
    if not CJK.search(text):
        return 0, []
    spans = comment_spans(text)
    hits = []

    def repl(m):
        if in_spans(m.start(), spans):
            return m.group(0)
        quote = m.group(0)[0]
        idx = {'"': 1, "'": 2, '`': 3}[quote]
        body = m.group(idx)
        if body is None or not CJK.search(body):
            return m.group(0)
        if body not in table:
            return m.group(0)
        english = validate_literal_body(table[body], quote)
        hits.append((body, english))
        return quote + english + quote

    try:
        out = LITERAL.sub(repl, text)
    except ValueError as exc:
        raise ValueError(f'{path}: {exc}') from exc
    if hits and not dry_run:
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(out)
    return len(hits), hits


def coverage(root, layer=None):
    """Unique untranslated literals per layer, so progress is measurable."""
    per_layer = Counter()
    uniq = {}
    for full, rel in source_files(root, layer):
        with open(full, encoding='utf-8') as fh:
            text = fh.read()
        if not CJK.search(text):
            continue
        spans = comment_spans(text)
        L = layer_of(rel)
        for m in LITERAL.finditer(text):
            if in_spans(m.start(), spans):
                continue
            body = m.group(1) or m.group(2) or m.group(3) or ''
            if CJK.search(body):
                per_layer[L] += 1
                uniq.setdefault(body, (rel, len(CJK.findall(body))))
    print('Untranslated string literals still in source:\n')
    print(f'{"layer":10} {"occurrences":>12}')
    for L, n in per_layer.most_common():
        print(f'{L:10} {n:12,}')
    print(f'\nunique literals : {len(uniq):,}')
    print(f'Chinese chars   : {sum(c for _, c in uniq.values()):,}')
    return uniq


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root')
    ap.add_argument('dictionary', nargs='?')
    ap.add_argument('--layer', choices=('prompt', 'tooldesc', 'ui', 'apimsg', 'test'))
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--coverage', action='store_true')
    ap.add_argument('--allow-protected', action='store_true',
                    help='permit entries that collide with a sentinel (you must have '
                         'updated every consumer in the same commit)')
    args = ap.parse_args()

    if not os.path.isdir(args.root):
        print(f'not a directory: {args.root}', file=sys.stderr)
        return 2
    if args.coverage:
        coverage(args.root, args.layer)
        return 0
    if not args.dictionary:
        ap.error('a dictionary is required unless --coverage is given')

    with open(args.dictionary, encoding='utf-8') as fh:
        table = json.load(fh)
    table = {k: v for k, v in table.items() if not k.startswith('_')}

    bad = [k for k in table if k in PROTECTED]
    if bad and not args.allow_protected:
        print('Refusing to run: the dictionary touches protected sentinels.\n', file=sys.stderr)
        for k in bad:
            print(f'  {k!r}\n      {PROTECTED[k]}', file=sys.stderr)
        print('\nRemove them, or pass --allow-protected once every consumer is updated.',
              file=sys.stderr)
        return 1
    left = [k for k, v in table.items() if CJK.search(v)]
    if left:
        print(f'warning: {len(left)} entries still contain Chinese in their value, '
              f'e.g. {left[0]!r}', file=sys.stderr)

    total = 0
    touched = 0
    applied = Counter()
    for full, rel in source_files(args.root, args.layer):
        n, hits = apply_file(full, table, args.dry_run)
        if n:
            touched += 1
            total += n
            applied[layer_of(rel)] += n
            print(f'{"would patch" if args.dry_run else "patched"} {rel}: {n}')
    print(f'\n{total} replacements in {touched} files'
          f'{" (dry run, nothing written)" if args.dry_run else ""}')
    for L, n in applied.most_common():
        print(f'  {L:10} {n:6,}')
    used = {k for k in table if any(True for _ in [0])}
    print(f'\ndictionary entries: {len(table):,}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
