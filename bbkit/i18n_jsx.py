#!/usr/bin/env python3
"""Translate Chinese JSX text in ARTEX's frontend — the part i18n_apply.py cannot see.

i18n_apply.py replaces quoted string literals. Most visible UI text is not
quoted at all: it sits between tags, <Label>用户名</Label>, or runs as a
multi-line paragraph inside <p>…</p>. That is JSX text, and in this codebase
it outweighs the quoted strings. This tool handles it.

A JSX text segment is a run of characters bounded on the left by '>' or '}'
and on the right by '<' or '{', outside every comment and string literal. So
`共 {n} 个任务` yields two segments, "共 " and " 个任务", translated
independently — reordering across an expression is done by mapping one of them
to an empty string.

The dictionary key is the segment with its whitespace collapsed to single
spaces (JSX renders it collapsed anyway); the replacement keeps the segment's
original leading and trailing whitespace so layout between neighbouring
elements does not shift.

    python3 bbkit/i18n_jsx.py ARTEX/web/src extract keys.json
    python3 bbkit/i18n_jsx.py ARTEX/web/src apply dict.json --dry-run
    python3 bbkit/i18n_jsx.py ARTEX/web/src apply dict.json
    python3 bbkit/i18n_jsx.py ARTEX/web/src coverage
"""
import argparse
import json
import os
import re
import sys
from collections import Counter

CJK = re.compile(r'[一-鿿]')
LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`[^`]*`', re.S)
LINE_COMMENT = re.compile(r'//[^\n]*')
BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)
JSX_COMMENT = re.compile(r'\{/\*.*?\*/\}', re.S)
RUN = re.compile(r'[^<>{}]+')
WS = re.compile(r'\s+')

# Values may not contain these: each one would open or close JSX syntax.
FORBIDDEN = set('{}<>')


def masked(text):
    """Return text with every comment and string literal blanked to spaces.

    Offsets are preserved (newlines are kept), so a JSX text run found in the
    masked copy maps straight back onto the original. Blanking first is the
    point: a check that only asks whether a run's first and last characters sit
    inside a comment misses a comment in the MIDDLE of the run — exactly how
    code such as `case "done": // 完成` used to be picked up as UI text.

    A '//' is treated as a URL rather than a comment when the character right
    before it is ':' (https://…), which is how a link inside JSX text survives.
    """
    spans = []
    # A JSX comment {/* … */} keeps its braces: blanking them would let a text
    # run flow straight through the comment, and translating that run would
    # silently delete the comment along with the Chinese around it.
    spans.extend((m.start() + 1, m.end() - 1) for m in JSX_COMMENT.finditer(text))
    for rx in (BLOCK_COMMENT, LITERAL):
        spans.extend((m.start(), m.end()) for m in rx.finditer(text))
    for m in LINE_COMMENT.finditer(text):
        if m.start() > 0 and text[m.start() - 1] == ':':
            continue
        spans.append((m.start(), m.end()))
    buf = list(text)
    for a, b in spans:
        for i in range(a, b):
            if buf[i] != '\n':
                buf[i] = ' '
    return ''.join(buf)


def segments(text):
    """Yield (start, end, raw) for every JSX text segment containing Chinese.

    Runs are found on the masked copy, so only Chinese that is genuinely
    outside comments and string literals counts. Code between an arrow '=>' or
    a generic '>' and the next '{' still forms a run, but after masking it
    carries no Chinese and is skipped.
    """
    m_text = masked(text)
    for m in RUN.finditer(m_text):
        if not CJK.search(m.group(0)):
            continue
        s, e = m.start(), m.end()
        left = m_text[s - 1] if s > 0 else ''
        right = m_text[e] if e < len(m_text) else ''
        if left not in '>}' or right not in '<{':
            continue
        yield s, e, text[s:e]


def key_of(raw):
    return WS.sub(' ', raw.strip())


def tsx_files(root):
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d not in ('node_modules', '.next', 'mock')]
        for fn in fns:
            if fn.endswith('.tsx'):
                yield os.path.join(dp, fn)


def cmd_extract(root, out):
    seen = Counter()
    for p in tsx_files(root):
        with open(p, encoding='utf-8') as fh:
            text = fh.read()
        for _, _, raw in segments(text):
            seen[key_of(raw)] += 1
    keys = sorted(seen, key=lambda k: (len(k), k))
    with open(out, 'w', encoding='utf-8') as fh:
        json.dump({k: '' for k in keys}, fh, ensure_ascii=False, indent=1)
    chars = sum(len(CJK.findall(k)) for k in keys)
    print(f'{sum(seen.values())} segments, {len(keys)} unique, {chars:,} Chinese chars -> {out}')


def validate(value):
    # JSX text has no escape sequences: a backslash renders literally, so \" in
    # a value shows up on screen as a backslash and a quote. It parses fine, so
    # neither a dry run nor a syntax check would notice — reject it here.
    if '\\' in value:
        raise ValueError(f'value contains a backslash, which JSX text renders literally '
                         f'(write a bare " instead of \\"): {value[:60]!r}')
    bad = FORBIDDEN.intersection(value)
    if bad:
        raise ValueError(f'value contains {"".join(sorted(bad))}, which would break JSX: '
                         f'{value[:60]!r}')


def cmd_apply(root, dictionary, dry_run):
    with open(dictionary, encoding='utf-8') as fh:
        table = {k: v for k, v in json.load(fh).items() if not k.startswith('_')}
    for v in table.values():
        validate(v)
    total = files = 0
    for p in tsx_files(root):
        with open(p, encoding='utf-8') as fh:
            text = fh.read()
        hits = [(s, e, raw) for s, e, raw in segments(text) if key_of(raw) in table]
        if not hits:
            continue
        out = []
        prev = 0
        for s, e, raw in hits:
            lead = raw[:len(raw) - len(raw.lstrip())]
            trail = raw[len(raw.rstrip()):]
            out.append(text[prev:s])
            out.append(lead + table[key_of(raw)] + trail)
            prev = e
        out.append(text[prev:])
        if not dry_run:
            with open(p, 'w', encoding='utf-8') as fh:
                fh.write(''.join(out))
        files += 1
        total += len(hits)
        print(f'{"would patch" if dry_run else "patched"} {os.path.relpath(p, root)}: {len(hits)}')
    print(f'\n{total} segments in {files} files{" (dry run)" if dry_run else ""}')


def cmd_coverage(root):
    seen = Counter()
    for p in tsx_files(root):
        with open(p, encoding='utf-8') as fh:
            text = fh.read()
        for _, _, raw in segments(text):
            seen[key_of(raw)] += 1
    print(f'JSX text still Chinese: {sum(seen.values())} segments, {len(seen)} unique, '
          f'{sum(len(CJK.findall(k)) for k in seen):,} chars')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root')
    sub = ap.add_subparsers(dest='cmd', required=True)
    e = sub.add_parser('extract'); e.add_argument('out')
    a = sub.add_parser('apply'); a.add_argument('dictionary'); a.add_argument('--dry-run', action='store_true')
    sub.add_parser('coverage')
    args = ap.parse_args()
    if args.cmd == 'extract':
        cmd_extract(args.root, args.out)
    elif args.cmd == 'apply':
        try:
            cmd_apply(args.root, args.dictionary, args.dry_run)
        except ValueError as exc:
            print(f'refusing: {exc}', file=sys.stderr)
            return 1
    else:
        cmd_coverage(args.root)
    return 0


if __name__ == '__main__':
    sys.exit(main())
