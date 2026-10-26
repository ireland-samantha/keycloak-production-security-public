#!/usr/bin/env python3
"""Narrow public-package content screen. Not a complete secret scanner or IP review."""
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Every added file needs explicit review here and in the package manifest.
FILES = {
    '.gitattributes', '.gitignore', '.github/CODEOWNERS', '.github/dependabot.yml',
    '.github/ISSUE_TEMPLATE/bug_report.yml', '.github/ISSUE_TEMPLATE/config.yml',
    '.github/ISSUE_TEMPLATE/feature_request.yml', '.github/workflows/test.yml',
    'AGENTS.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'PACKAGE-MANIFEST.sha256',
    'README.md', 'RELEASE.json', 'RELEASE-REVIEW.md', 'SECURITY.md', 'SKILL.md', 'action.yml',
    'assets/input-schema.json', 'assets/review-schema.json',
    'references/deployment-contract.md', 'references/inventory-adapter.md',
    'references/product-guide.md', 'references/report-template.md',
    'scripts/keycloak_guard.py', 'scripts/test_keycloak_guard.py',
    'scripts/test_public_release.py', 'scripts/release_check.py',
}
PATTERNS = {
    'private-key': r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----',
    'github-token': r'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}',
    'cloud-key': r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|AIza[A-Za-z0-9_-]{30,}',
    'provider-key': r'\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}',
    'jwt': r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'credential-url': r'\b[a-z]+://[^\s/:]+:[^\s/@]+@',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
}
HOSTS = {'github.com', 'docs.github.com', 'www.keycloak.org', 'json-schema.org', 'csrc.nist.gov'}


def verify(root=ROOT):
    problems = []
    actual = set()
    for path in root.rglob('*'):
        rel = path.relative_to(root)
        if '.git' in rel.parts:
            continue
        if path.is_symlink():
            problems.append(f'{rel}: symlink')
        elif path.is_file():
            actual.add(rel.as_posix())
    if actual != FILES:
        problems.append(f'file inventory differs: {sorted(actual ^ FILES)}')
    hashes = {}
    for name in sorted(actual & FILES):
        data = (root / name).read_bytes()
        try:
            text = data.decode('utf-8')
        except UnicodeError:
            problems.append(f'{name}: non-text content')
            continue
        if b'\0' in data or len(data) > 128 * 1024 or len(text.splitlines()) > 500:
            problems.append(f'{name}: content bounds')
        if name.endswith('.json'):
            json.loads(text)
        for rule, pattern in PATTERNS.items():
            if re.search(pattern, text):
                problems.append(f'{name}: {rule}')
        for host in re.findall(r'https?://([A-Za-z0-9.-]+)', text):
            if host not in HOSTS:
                problems.append(f'{name}: unreviewed remote host')
        for value in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text):
            try:
                address = ipaddress.ip_address(value)
                if address.is_private or address.is_loopback or address.is_link_local:
                    problems.append(f'{name}: nonpublic IP literal')
            except ValueError:
                pass
        hashes[name] = hashlib.sha256(data).hexdigest()
    manifest = {}
    for line in (root / 'PACKAGE-MANIFEST.sha256').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match or match[2] in manifest:
            problems.append('invalid or duplicate manifest entry')
            continue
        manifest[match[2]] = match[1]
    expected = {name: value for name, value in hashes.items() if name != 'PACKAGE-MANIFEST.sha256'}
    if manifest != expected:
        problems.append('manifest file set or byte hashes differ')
    if (root / '.git').exists():
        tracked = set(subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')) - {''}
        if tracked != FILES:
            problems.append('Git index file set differs')
    if problems:
        raise ValueError('\n'.join(problems))
    return len(actual)


if __name__ == '__main__':
    try:
        count = verify()
        print(f'PASS: {count} allowlisted text files; manifest and narrow content checks match')
    except (ValueError, OSError) as error:
        print(f'REFUSED: {error}', file=sys.stderr)
        sys.exit(2)
