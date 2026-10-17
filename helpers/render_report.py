#!/usr/bin/env python3
"""Lay out an already-completed check overview. No lookups or assessments."""

import argparse
import collections
import os
import re
import sys
import unicodedata
from dataclasses import dataclass


@dataclass
class Row:
    status: str
    label: str
    value: str


def cells(text):
    return sum(0 if unicodedata.combining(c) else
               2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1
               for c in text)


def wrap(text, width):
    """Wrap without dropping characters, including long DNS/TXT/IPv6 values."""
    lines, start = [], 0
    while start < len(text):
        end, used = start, 0
        while end < len(text) and used + cells(text[end]) <= width:
            used += cells(text[end])
            end += 1
        end = max(start + 1, end)
        if end < len(text):
            space = text.rfind(' ', start, end)
            if space > start:
                end = space + 1
        lines.append(text[start:end])
        start = end
    if not lines:
        lines.append('')
    return lines


def safe(text):
    # Terminal controls must not be able to escape a panel or change its width.
    return ''.join(c if not unicodedata.category(c).startswith('C') else
                   f'\\x{ord(c):02x}' for c in text)


def parse(text):
    sections = collections.OrderedDict()
    section = None
    counts = collections.Counter()
    for line in text.splitlines():
        if line.startswith('== '):
            section = line[3:]
            sections.setdefault(section, [])
            continue
        if not line.strip():
            continue
        if section is None:
            raise ValueError('Not an overview report')
        match = re.match(r'^\s*\[(OK|!|X|i)\]\s+(.*)$', line)
        status, value = (match.group(1), match.group(2)) if match else ('', line.strip())
        if status:
            counts[status] += 1
        sections[section].append((status, safe(value)))
    required = {'REGISTRAR', 'DNS', 'MAIL & SECURITY POLICY', 'HOSTING', 'TLS', 'HTTP / HTTPS'}
    if not required <= sections.keys() or sections.keys() - required - {'REVERSE DNS'}:
        raise ValueError('Incomplete overview report')
    return sections, counts


def record_rows(section, records):
    rows = []
    for status, text in records:
        label, value = '', text
        match = re.match(r'^(A|AAAA|NS|CNAME|MX|CAA|SPF contains|DMARC policy): (.*)$', text)
        if match:
            label, value = match.groups()
            label = {'SPF contains': 'SPF', 'DMARC policy': 'DMARC'}.get(label, label)
        elif text.startswith('DNSSEC '):
            label, value = 'DNSSEC', text[7:]
        elif section == 'MAIL & SECURITY POLICY':
            match = re.match(r'^(SPF|DMARC|CAA) (.*)$', text)
            if match:
                label, value = match.groups()
        elif section == 'TLS':
            match = re.match(r'^(Issuer|CN|Certificate expiry)\s+(.*)$', text)
            if match:
                label, value = match.groups()
                label = {'CN': 'Name', 'Certificate expiry': 'Expires'}.get(label, label)
            elif text.startswith('Certificate hostname '):
                label, value = 'Hostname', text[len('Certificate hostname '):]
            elif text.startswith('Certificate expires in '):
                label, value = 'Expires', text[len('Certificate expires in '):]
            elif text.startswith('Certificate expired: '):
                label, value = 'Expired', text[len('Certificate expired: '):]
        elif section == 'HTTP / HTTPS':
            match = re.match(r'^(HTTP|HTTPS)\s+([0-9]{3})$', text)
            if match:
                label, value = match.groups()
            else:
                for prefix, name in (
                    ('HTTP redirects to HTTPS → ', 'Redirect'),
                    ('HTTP redirects, but not clearly to HTTPS → ', 'Redirect'),
                    ('HTTPS redirect → ', 'HTTPS hop'),
                    ('Content-Security-Policy ', 'CSP'),
                    ('Server header ', 'Server'),
                    ('X-Powered-By ', 'X-Powered-By'),
                    ('HSTS', 'HSTS'),
                ):
                    if text.startswith(prefix):
                        label, value = name, text[len(prefix):].lstrip(': ')
                        if prefix.startswith('HTTP redirects to HTTPS'):
                            value = 'HTTPS → ' + value
                        elif prefix.startswith('HTTP redirects,'):
                            value = 'Not clearly HTTPS → ' + value
                        break
        elif section == 'REVERSE DNS' and ' → ' in text:
            label, value = text.split(' → ', 1)
        rows.append(Row(status, label, value))
    return rows


class Layout:
    COLORS = {
        'edge': (59, 66, 97), 'text': (192, 202, 245),
        'muted': (145, 156, 194), 'label': (125, 207, 255),
        'title': (122, 162, 247), 'OK': (158, 206, 106),
        '!': (224, 175, 104), 'X': (247, 118, 142), 'i': (187, 154, 247),
    }

    def __init__(self, width, color, ascii_mode):
        self.width = min(124, max(24, width))
        self.color = color
        self.ascii = ascii_mode
        self.truecolor = os.environ.get('COLORTERM') in ('truecolor', '24bit')
        self.tl, self.tr, self.bl, self.br, self.h, self.v = (
            ('+', '+', '+', '+', '-', '|') if ascii_mode else
            ('╭', '╮', '╰', '╯', '─', '│'))

    def paint(self, text, role='text', bold=False):
        if not self.color:
            return text
        rgb = self.COLORS[role]
        # The existing suite already assumes at least 256-color support.
        if self.truecolor:
            code = '38;2;' + ';'.join(map(str, rgb))
        else:
            cube = [round(c / 255 * 5) for c in rgb]
            code = f'38;5;{16 + 36 * cube[0] + 6 * cube[1] + cube[2]}'
        return f'\033[{"1;" if bold else ""}{code}m{text}\033[0m'

    def glyph(self, status):
        return ({'OK': '+', '!': '!', 'X': 'x', 'i': 'i'} if self.ascii else
                {'OK': '✓', '!': '!', 'X': '×', 'i': '·'}).get(status, ' ')

    def border(self, width, title=None, bottom=False):
        if bottom:
            return self.paint(self.bl + self.h * (width - 2) + self.br, 'edge')
        caption = f' {title} ' if title else ''
        return (self.paint(self.tl + self.h, 'edge') +
                self.paint(caption, 'title', True) +
                self.paint(self.h * max(0, width - 3 - cells(caption)) + self.tr, 'edge'))

    def enclosed(self, segments, used, width):
        return (self.paint(self.v, 'edge') + ' ' + ''.join(segments) +
                ' ' * max(0, width - 4 - used) + ' ' + self.paint(self.v, 'edge'))

    def panel(self, title, rows, width, reverse=False):
        # Reserve a compact label column; PTR addresses can use more room.
        inner = width - 4
        label_width = min(max((cells(r.label) for r in rows), default=0),
                          39 if reverse else 12, max(0, inner // 2 - 2))
        value_width = max(1, inner - label_width - 4)
        output = [self.border(width, title)]
        previous = None
        for row in rows:
            repeat = row.label == previous and row.label in {'A', 'AAAA', 'NS', 'CNAME', 'MX', 'CAA'}
            label = '' if repeat else row.label
            labels = wrap(label, max(1, label_width))
            values = wrap(row.value, value_width)
            for index in range(max(len(labels), len(values))):
                key = labels[index] if index < len(labels) else ''
                value = values[index] if index < len(values) else ''
                mark = self.glyph(row.status) if index == 0 else ' '
                prefix = mark + ' ' + key + ' ' * (label_width - cells(key)) + '  '
                segments = [self.paint(mark, row.status or 'muted') + ' ',
                            self.paint(key + ' ' * (label_width - cells(key)), 'muted'),
                            '  ', self.paint(value)]
                output.append(self.enclosed(segments, cells(prefix) + cells(value), width))
            previous = row.label
        output.append(self.border(width, bottom=True))
        return output

    def header(self, host, sections):
        width = self.width
        lines = [self.border(width, 'DOMAIN REPORT')]
        for part in wrap(safe(host), width - 4):
            lines.append(self.enclosed([self.paint(part, 'text', True)], cells(part), width))
        for section, label in [('REGISTRAR', 'Registrar'), ('HOSTING', 'Hosting')]:
            for status, text in sections[section]:
                if section == 'HOSTING' and text.startswith('Guessing: '):
                    text = text[len('Guessing: '):]
                    if text != 'Unknown':
                        text += ' (inferred)'
                prefix = f'{label:<11}'
                room = width - 4 - len(prefix) - 2
                for i, part in enumerate(wrap(text, max(1, room))):
                    key = prefix if i == 0 else ' ' * len(prefix)
                    mark = self.glyph(status) if i == 0 else ' '
                    segments = [self.paint(key, 'muted'), self.paint(mark, status or 'muted'),
                                ' ', self.paint(part)]
                    lines.append(self.enclosed(segments, len(key) + 2 + cells(part), width))
        lines.append(self.border(width, bottom=True))
        return lines

    def pair(self, left, right):
        if self.width < 110:
            return self.panel(*left, self.width) + [''] + self.panel(*right, self.width)
        left_width = (self.width - 2) // 2
        right_width = self.width - 2 - left_width
        a, b = self.panel(*left, left_width), self.panel(*right, right_width)
        height = max(len(a), len(b))
        a[-1:-1] = [self.enclosed([], 0, left_width)] * (height - len(a))
        b[-1:-1] = [self.enclosed([], 0, right_width)] * (height - len(b))
        return [x + '  ' + y for x, y in zip(a, b)]

    def render(self, host, sections, counts):
        rows = {name: record_rows(name, records) for name, records in sections.items()}
        lines = [''] + self.header(host, sections) + ['']
        lines += self.pair(('DNS RECORDS', rows['DNS']), ('MAIL & POLICY', rows['MAIL & SECURITY POLICY']))
        lines += [''] + self.pair(('TLS CERTIFICATE', rows['TLS']), ('HTTP & HTTPS', rows['HTTP / HTTPS']))
        if 'REVERSE DNS' in rows:
            lines += [''] + self.panel('REVERSE DNS', rows['REVERSE DNS'], self.width, reverse=True)
        lines.append('')
        summary = [(self.paint('OBSERVATIONS', 'muted'), 12)]
        for status, label in [('OK', 'OK'), ('!', 'WARN'), ('X', 'FAIL'), ('i', 'INFO')]:
            text = f'{self.glyph(status)} {counts[status]} {label}'
            summary.append((self.paint(text, status), cells(text)))
        # Each item fits even very narrow terminals; do not truncate counts.
        line, used = '', 0
        for item, length in summary:
            if used and used + 3 + length > self.width:
                lines.append(line)
                line, used = '', 0
            line += ('   ' if used else '') + item
            used += (3 if used else 0) + length
        lines.append(line)
        return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--width', type=int, default=80)
    parser.add_argument('--color', choices=['0', '1'], default='0')
    parser.add_argument('--ascii', choices=['0', '1'], default='0')
    ARGS = parser.parse_args()
    try:
        SECTIONS, COUNTS = parse(sys.stdin.read())
        sys.stdout.write(Layout(ARGS.width, ARGS.color == '1', ARGS.ascii == '1').render(ARGS.host, SECTIONS, COUNTS))
    except ValueError as error:
        print(f'Report layout unavailable: {error}', file=sys.stderr)
        raise SystemExit(1)
