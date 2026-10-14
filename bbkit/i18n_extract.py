#!/usr/bin/env python3
"""Catalogue every Chinese string in ARTEX, by layer and by risk.

Translating 214k characters blind is how you break a working tool. This splits
the job into layers that differ by *consequence*, and flags the strings that are
protocol rather than prose — a value some other file compares against, where a
translation silently changes behaviour instead of changing words.

    python3 bbkit/i18n_extract.py ARTEX                 # summary
    python3 bbkit/i18n_extract.py ARTEX --layer prompt  # one layer
    python3 bbkit/i18n_extract.py ARTEX --tsv out.tsv   # reviewable catalogue
    python3 bbkit/i18n_extract.py ARTEX --risky         # only the dangerous ones

Layers, in the order worth doing them:

  prompt     agent/promptcatalog.go, planner.go, worker.go, goals.go,
             intercept/prompt.go — the text that drives the LLM. Seeded into
             agent_prompts (db/config.go:743 SeedPromptIfEmpty), so on a live
             install these are edited through PUT /api/agents/{key}/prompt and
             need NO rebuild.
  tooldesc   agent/tools*.go, toolcatalog.go — tool names/descriptions the model
             reads to choose a tool. Seeded into the tools table; editable via
             PUT /api/tools/{key}.
  ui         web/src/** — what you see. Hardcoded in JSX (no i18n framework in
             web/package.json), so this one needs a frontend rebuild.
  apimsg     server/**, db/**, notify/** non-comment strings — API errors and
             log lines. Needs a Go rebuild.
  comment    Go/TS comments. Zero functional effect. Do last or never.
  test       *_test.go and mock data. Translating production strings breaks the
             tests that assert on them — expect to update both together.
"""
import argparse
import csv
import os
import re
import sys
from collections import Counter

CJK = re.compile(r'[一-鿿]')

# A Chinese literal consumed by one of these is a sentinel, not a label.
RISKY = re.compile(
    r'(?:[!=]=\s*"[^"]*[一-鿿]|'
    r'case\s+"[^"]*[一-鿿]|'
    r'(?:Contains|HasPrefix|HasSuffix|EqualFold)\(\s*[^,)]+,\s*"[^"]*[一-鿿]|'
    r'\[\s*"[^"]*[一-鿿][^"]*"\s*\])'
)

# Terms that must stay Chinese: they are the thing itself, not a translation of it.
KEEP = {
    '备案': 'ICP filing — a Chinese regulatory concept; db/company_scope.go matches this '
            'keyword to classify a scope entry. Translating it breaks the feature.',
    '[模型]': 'Sentinel marking a model-made decision. Produced in intercept/, consumed in '
              'intercept/intercept.go, db/intercept.go and db/task_archives_restore.go — '
              'change all four together or none.',
}

PROMPT_FILES = (
    'agent/promptcatalog.go', 'agent/planner.go', 'agent/worker.go', 'agent/goals.go',
    'agent/prompt.go', 'agent/mainagent.go', 'agent/retester.go', 'intercept/prompt.go',
)
TOOLDESC_FILES = ('agent/tools.go', 'agent/tools_insert.go', 'agent/tools_digest.go',
                  'agent/toolcatalog.go')

LINE_COMMENT = re.compile(r'//.*$')


def layer_of(relpath, in_comment):
    norm = relpath.replace(os.sep, '/')
    if norm.endswith('_test.go') or '.test.' in norm or '/mock/' in norm:
        return 'test'
    if in_comment:
        return 'comment'
    if norm in PROMPT_FILES:
        return 'prompt'
    if norm in TOOLDESC_FILES:
        return 'tooldesc'
    if norm.startswith('web/'):
        return 'ui'
    if norm.endswith('.go'):
        return 'apimsg'
    return 'other'


def scan(root):
    rows = []
    exts = ('.go', '.tsx', '.ts', '.sql', '.sh', '.bat', '.js', '.mjs', '.py', '.json', '.yml')
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('.git', 'node_modules', '.next', 'dist')]
        for fn in filenames:
            if not fn.endswith(exts):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            try:
                with open(full, encoding='utf-8') as fh:
                    lines = fh.readlines()
            except (OSError, UnicodeDecodeError):
                continue
            for i, line in enumerate(lines, 1):
                if not CJK.search(line):
                    continue
                stripped = line.strip()
                # Comment-only lines are prose; a trailing comment on a code line
                # is still counted as code so its string literal is not missed.
                in_comment = stripped.startswith(('//', '#', '*', '/*'))
                if not in_comment and LINE_COMMENT.search(line):
                    code_part = LINE_COMMENT.sub('', line)
                    in_comment = not CJK.search(code_part)
                keep = [term for term in KEEP if term in line]
                rows.append({
                    'layer': layer_of(rel, in_comment),
                    'risky': 'YES' if RISKY.search(line) else '',
                    'keep': ','.join(keep),
                    'file': rel,
                    'line': i,
                    'chars': len(CJK.findall(line)),
                    'text': stripped[:300],
                })
    return rows


ORDER = ['prompt', 'tooldesc', 'ui', 'apimsg', 'test', 'comment', 'other']


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root', help='path to the ARTEX checkout')
    ap.add_argument('--layer', help='show only this layer')
    ap.add_argument('--risky', action='store_true', help='show only sentinel-risk lines')
    ap.add_argument('--tsv', help='write the full catalogue here')
    ap.add_argument('--limit', type=int, default=40)
    args = ap.parse_args()

    if not os.path.isdir(args.root):
        print(f'not a directory: {args.root}', file=sys.stderr)
        return 2

    rows = scan(args.root)
    if not rows:
        print('no Chinese text found — already translated?')
        return 0

    if args.tsv:
        with open(args.tsv, 'w', newline='', encoding='utf-8') as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]), delimiter='\t')
            w.writeheader()
            w.writerows(rows)
        print(f'[wrote {args.tsv}: {len(rows)} lines]\n')

    sel = rows
    if args.layer:
        sel = [r for r in sel if r['layer'] == args.layer]
    if args.risky:
        sel = [r for r in sel if r['risky']]

    if not args.layer and not args.risky:
        chars = Counter()
        lines = Counter()
        files = {}
        for r in rows:
            chars[r['layer']] += r['chars']
            lines[r['layer']] += 1
            files.setdefault(r['layer'], set()).add(r['file'])
        total = sum(chars.values())
        print('Layer      chars      lines  files   share  rebuild needed')
        print('-' * 62)
        for layer in ORDER:
            if not chars[layer]:
                continue
            need = {'prompt': 'no — DB', 'tooldesc': 'no — DB', 'ui': 'yes — frontend',
                    'apimsg': 'yes — Go', 'test': 'yes — Go', 'comment': 'no effect',
                    'other': '-'}[layer]
            print(f'{layer:10} {chars[layer]:7,} {lines[layer]:10,} {len(files[layer]):6} '
                  f'{chars[layer] * 100 // total:5}%   {need}')
        print('-' * 62)
        print(f'{"TOTAL":10} {total:7,} {len(rows):10,}')

        risky = [r for r in rows if r['risky'] and r['layer'] not in ('test', 'comment')]
        print(f'\nSentinel-risk lines in production code: {len(risky)}')
        print('These are compared against elsewhere — translate the producer and every')
        print('consumer in the same commit, or leave them alone.')
        for r in risky:
            print(f'  {r["file"]}:{r["line"]}  {r["text"][:88]}')

        keeps = [r for r in rows if r['keep']]
        if keeps:
            print(f'\nMUST NOT translate ({len(keeps)} lines):')
            for term, why in KEEP.items():
                hits = [r for r in keeps if term in r['keep']]
                if hits:
                    print(f'  {term!r} — {len(hits)} lines')
                    print(f'      {why}')
        print('\nSuggested order: prompt -> tooldesc -> ui -> apimsg (+test) -> comment')
        print('Start with prompt + tooldesc: biggest behavioural win, no rebuild.')
        return 0

    sel.sort(key=lambda r: (r['file'], r['line']))
    for r in sel[:args.limit]:
        flag = ' [RISKY]' if r['risky'] else ''
        flag += f' [KEEP {r["keep"]}]' if r['keep'] else ''
        print(f'{r["file"]}:{r["line"]}{flag}\n    {r["text"]}')
    if len(sel) > args.limit:
        print(f'\n... {len(sel) - args.limit} more (raise --limit, or use --tsv)')
    print(f'\n{len(sel)} lines, {sum(r["chars"] for r in sel):,} Chinese characters')
    return 0


if __name__ == '__main__':
    sys.exit(main())
