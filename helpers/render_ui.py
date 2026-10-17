#!/usr/bin/env python3
"""Shared terminal documents for help, diagnostics and command results."""

import argparse
import re
import sys

from cli_catalog import help_document
from render_report import Layout, Row, safe

PREFIX = '\x1eDSU\t'
ESCAPES = {'\\': '\\', 't': '\t', 'n': '\n', 'r': '\r', 'x1e': '\x1e'}


def unescape(value):
    return re.sub(r'\\(x1e|[\\tnr])', lambda match: ESCAPES[match[1]], value)


def events(text):
    # splitlines() also splits on RS, which is our metadata prefix.
    lines = text.split('\n')
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith(PREFIX):
            kind, key, value, count = line[len(PREFIX):].split('\t', 3)
            count = int(count)
            if count < 1 or index + count >= len(lines):
                raise ValueError('Invalid presentation record length')
            yield kind, unescape(key), unescape(value)
            index += count + 1
        else:
            if line.strip():
                yield 'raw', '', line
            index += 1


def result_sections(text):
    sections = []
    title, rows = 'RESULT', []
    for kind, key, value in events(text):
        original_value = value
        key, value = safe(key), safe(value)
        if kind == 'section':
            if rows:
                sections.append((title, rows))
            title, rows = key, []
        elif kind == 'banner':
            if not rows:
                title = 'CONTEXT'
        elif kind == 'field':
            rows.append(Row('', key, value))
        elif kind == 'finding':
            status = {'CRITICAL': 'X', 'HIGH': 'X', 'MEDIUM': '!', 'LOW': 'i', 'INFO': 'i'}.get(key, 'i')
            rows.append(Row(status, key, value))
        elif kind == 'summary':
            counts = key.split()
            if len(counts) != 5 or not all(count.isdigit() for count in counts):
                raise ValueError('Invalid finding totals')
            rows.extend(Row('', label, count) for label, count in
                        zip(['Critical', 'High', 'Medium', 'Low', 'Info'], counts))
        elif kind == 'status':
            label = ''
            match = re.match(r'^([^:]{1,28}): (.*)$', value)
            if match:
                label, value = match.groups()
            rows.append(Row(key if key in ('OK', '!', 'X', 'i') else 'i', label, value))
        elif kind == 'raw' and title.startswith('Certificate Transparency') and original_value.count('\t') == 2:
            name, expiry, issuer = original_value.split('\t')
            rows.append(Row('', safe(name), safe(expiry + ' | ' + issuer)))
        elif kind == 'raw':
            text = safe(original_value.expandtabs(4))
            match = re.match(r'^([^:]{1,22}): (.*)$', text.strip())
            rows.append(Row('', *match.groups()) if match else Row('', '', text))
        elif kind == 'text':
            rows.append(Row('', '', value))
        else:
            raise ValueError('Unrecognized presentation record')
    if rows:
        sections.append((title, rows))
    return sections


def header(layout, command, target='', description='', help_mode=False):
    rows = [Row('', 'Command', safe(command))]
    if target:
        rows.append(Row('', 'Target', safe(target)))
    if description:
        rows.append(Row('', '', description))
    return '\n'.join([''] + layout.panel('HELP' if help_mode else 'COMMAND', rows, layout.width, label_role='label'))


def help_text(layout, family, topic, plain=False):
    command, description, sections = help_document(family, topic)
    if plain:
        lines = [layout.paint(command, 'title', True), layout.paint(description, 'muted')]
        for title, items in sections:
            lines += ['', layout.paint(title, 'title', True)]
            lines += [('  ' + layout.paint(label.ljust(27), 'label') + value) if label else '  ' + value for label, value in items]
        return '\n'.join(lines)
    lines = [header(layout, command, description=description, help_mode=True)]
    cards = [(title, [Row('', label, value[7:] if title == 'USAGE' and value.startswith('Usage: ') else value)
                      for label, value in items]) for title, items in sections]
    lines += [''] + layout.panel(*cards[0], layout.width, label_role='label')
    remaining = cards[1:]
    for i in range(0, len(remaining), 2):
        if i + 1 < len(remaining):
            lines += [''] + layout.pair(remaining[i], remaining[i + 1], label_limit=27, label_role='label')
        else:
            lines += [''] + layout.panel(*remaining[i], layout.width, label_limit=27, label_role='label')
    return '\n'.join(lines)


def render_result(layout, text, rc):
    lines = []
    for title, rows in result_sections(text):
        lines += [''] + layout.panel(title, rows, layout.width, label_limit=22)
    if not lines:
        lines += [''] + layout.panel('RESULT', [Row('', '', 'No standard output.')], layout.width)
    if rc:
        lines += ['', layout.paint(f'Exit status: {rc}', 'muted')]
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['help', 'header', 'result'])
    parser.add_argument('--family', default='check')
    parser.add_argument('--topic', default='')
    parser.add_argument('--command', default='check')
    parser.add_argument('--target', default='')
    parser.add_argument('--width', type=int, default=80)
    parser.add_argument('--color', choices=['0', '1'], default='0')
    parser.add_argument('--ascii', choices=['0', '1'], default='0')
    parser.add_argument('--plain', action='store_true')
    parser.add_argument('--exit-code', type=int, default=0)
    args = parser.parse_args()
    layout = Layout(args.width, args.color == '1', args.ascii == '1')
    try:
        if args.mode == 'help':
            output = help_text(layout, args.family, args.topic, args.plain)
        elif args.mode == 'header':
            output = header(layout, args.command, args.target)
        else:
            output = render_result(layout, sys.stdin.buffer.read().decode('utf-8', 'replace'), args.exit_code)
        print(output)
    except (ValueError, KeyError) as error:
        print(f'Presentation unavailable: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
