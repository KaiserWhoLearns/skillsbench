#!/usr/bin/env bash
set -euo pipefail

mkdir -p /app/output

python3 - <<'PY'
import re

with open('/app/data/input.md', 'r') as f:
    content = f.read()

lines = content.split('\n')

# Extract H1 title
title = ""
title_idx = -1
for i, line in enumerate(lines):
    if line.startswith('# '):
        title = line[2:].strip()
        title_idx = i
        break

# Remove H1 line from body
if title_idx >= 0:
    lines = lines[:title_idx] + lines[title_idx+1:]

body = '\n'.join(lines).lstrip('\n')

# Convert code blocks with filename comments to use title attribute
def convert_codeblock(match):
    lang = match.group(1) or ''
    code = match.group(2)

    # Check for filename comment on first line: // file.ext or # file.ext
    filename_match = re.match(r'^(?://|#)\s*(\S+\.\w+)\s*\n', code)
    if filename_match:
        filename = filename_match.group(1)
        code = code[filename_match.end():]
        return f'```{lang} title="{filename}"\n{code}```'

    return f'```{lang}\n{code}```'

body = re.sub(r'```(\w*)\n(.*?)```', convert_codeblock, body, flags=re.DOTALL)

# Build output with frontmatter
output = f'''---
title: {title}
---

{body}'''

with open('/app/output/output.mdx', 'w') as f:
    f.write(output)

print("Conversion complete: /app/output/output.mdx")
PY
