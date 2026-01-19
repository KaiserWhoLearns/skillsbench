---
name: fumadocs-mdx
description: Transform Markdown to Fumadocs MDX format
---

# Fumadocs MDX Transformation

## H1 to Title

In Fumadocs, the H1 heading becomes the page title. Use YAML frontmatter:

```mdx
---
title: Page Title
---

Content starts here (no H1 in body).
```

## Code Block Titles

If a code block has a filename comment on the first line, convert it to a `title` attribute:

**Input:**
```javascript
// config.js
export default { debug: true };
```

**Output:**
```mdx
```javascript title="config.js"
export default { debug: true };
```​
```

Filename comments use `//` for JS/TS or `#` for bash/python.
