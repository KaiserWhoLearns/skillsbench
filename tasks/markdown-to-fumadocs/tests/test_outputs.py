"""Tests for markdown-to-fumadocs task."""

import re
from pathlib import Path

import pytest

INPUT_FILE = Path("/app/data/input.md")
OUTPUT_FILE = Path("/app/output/output.mdx")


@pytest.fixture(scope="module")
def input_content():
    """Load the input file."""
    return INPUT_FILE.read_text()


@pytest.fixture(scope="module")
def output_content():
    """Load the output file."""
    assert OUTPUT_FILE.exists(), f"Output file not found: {OUTPUT_FILE}"
    return OUTPUT_FILE.read_text()


@pytest.fixture(scope="module")
def input_h1(input_content):
    """Extract H1 title from input."""
    match = re.search(r'^# (.+)$', input_content, re.MULTILINE)
    return match.group(1) if match else None


@pytest.fixture(scope="module")
def input_code_blocks_with_filename(input_content):
    """Extract code blocks that have filename comments."""
    blocks = []
    for match in re.finditer(r'```(\w*)\n(.*?)```', input_content, re.DOTALL):
        lang = match.group(1)
        code = match.group(2)
        # Match filename comment: // filename.ext or # filename.ext
        filename_match = re.match(r'^(?://|#)\s*(\S+\.\w+)\s*\n', code)
        if filename_match:
            blocks.append({
                'lang': lang,
                'filename': filename_match.group(1),
                'comment_line': filename_match.group(0).strip(),
                'code_after_comment': code[filename_match.end():]
            })
    return blocks


# ============ Frontmatter Structure Tests ============

def test_output_has_frontmatter(output_content):
    """YAML frontmatter delimiters."""
    assert output_content.startswith('---'), "Valid mdx must start with frontmatter delimiter '---'"
    # Find closing delimiter (not the opening one)
    rest = output_content[3:].lstrip('\n')
    assert '\n---' in rest, "Output missing closing frontmatter delimiter '---'"


def test_frontmatter_contains_title_field(output_content, input_h1):
    """Frontmatter must contain a title field with the H1 value."""
    assert input_h1 is not None, "Input has no H1 heading"

    # Extract frontmatter content
    match = re.match(r'^---\n(.*?)\n---', output_content, re.DOTALL)
    assert match, "Could not parse frontmatter"
    frontmatter = match.group(1)

    # Check title field exists and contains the H1 text
    assert 'title:' in frontmatter or 'title :' in frontmatter, \
        "Frontmatter missing 'title' field"
    assert input_h1 in frontmatter, \
        f"Frontmatter title should contain '{input_h1}'"


# ============ H1 Removal Tests ============

def test_h1_removed_from_body(output_content, input_h1):
    """H1 heading must be removed from the body (not duplicated)."""
    assert input_h1 is not None, "Input has no H1 heading"

    # Extract body (content after frontmatter)
    match = re.match(r'^---\n.*?\n---\n(.*)$', output_content, re.DOTALL)
    assert match, "Could not extract body from output"
    body = match.group(1)

    # H1 markdown syntax should not appear in body
    h1_pattern = rf'^# {re.escape(input_h1)}\s*$'
    assert not re.search(h1_pattern, body, re.MULTILINE), \
        f"H1 '# {input_h1}' should be removed from body (moved to frontmatter)"


# ============ Code Block Title Tests ============

def test_code_blocks_have_title_attribute(output_content, input_code_blocks_with_filename):
    """Code blocks with filename comments must have title attribute."""
    assert len(input_code_blocks_with_filename) > 0, "Input has no code blocks with filenames"

    for block in input_code_blocks_with_filename:
        filename = block['filename']
        # Check title attribute exists
        assert f'title="{filename}"' in output_content, \
            f"Code block missing title=\"{filename}\" attribute"


def test_filename_comments_removed_from_code(output_content, input_code_blocks_with_filename):
    """Filename comments must be removed from code block content."""
    assert len(input_code_blocks_with_filename) > 0, "Input has no code blocks with filenames"

    for block in input_code_blocks_with_filename:
        filename = block['filename']
        comment_line = block['comment_line']

        # Find the code block with this title
        pattern = rf'```\w*\s+title="{re.escape(filename)}"[^\n]*\n(.*?)```'
        match = re.search(pattern, output_content, re.DOTALL)

        if match:
            code_content = match.group(1)
            # The original comment line should not be in the code
            assert comment_line not in code_content, \
                f"Filename comment '{comment_line}' should be removed from code block"


def test_code_content_preserved_after_title_extraction(output_content, input_code_blocks_with_filename):
    """Actual code content (after filename comment) must be preserved."""
    assert len(input_code_blocks_with_filename) > 0, "Input has no code blocks with filenames"

    for block in input_code_blocks_with_filename:
        # Get a significant line from the code (not the comment)
        code_lines = block['code_after_comment'].strip().split('\n')
        if code_lines:
            # Check first non-empty line of actual code is preserved
            first_code_line = code_lines[0].strip()
            if first_code_line:
                assert first_code_line in output_content, \
                    f"Code content '{first_code_line}' not preserved in output"


# ============ Content Preservation Tests ============

def test_h2_headings_preserved(output_content, input_content):
    """H2 and lower headings must be preserved in output."""
    h2_headings = re.findall(r'^(## .+)$', input_content, re.MULTILINE)
    assert len(h2_headings) > 0, "Input has no H2 headings to test"

    for h2 in h2_headings:
        assert h2 in output_content, f"H2 heading '{h2}' not preserved in output"


def test_paragraphs_preserved(output_content, input_content):
    """Non-code, non-heading paragraphs must be preserved."""
    # Find paragraphs (lines that aren't headings, code, or empty)
    paragraphs = []
    in_code_block = False
    for line in input_content.split('\n'):
        if line.startswith('```'):
            in_code_block = not in_code_block
            continue
        if not in_code_block and line.strip() and not line.startswith('#'):
            # Get first few words as a signature
            words = line.split()[:4]
            if len(words) >= 3:
                paragraphs.append(' '.join(words))

    for para_start in paragraphs[:2]:  # Check first 2 paragraphs
        assert para_start in output_content, \
            f"Paragraph starting with '{para_start}' not preserved"


# ============ MDX Validity Tests ============

def test_output_is_valid_mdx_structure(output_content):
    """Output must be valid MDX structure (frontmatter + content)."""
    # Must have frontmatter
    assert re.match(r'^---\n.*?\n---\n', output_content, re.DOTALL), \
        "Invalid MDX structure: must have frontmatter followed by content"

    # Code blocks must be properly closed
    open_blocks = len(re.findall(r'^```', output_content, re.MULTILINE))
    assert open_blocks % 2 == 0, "Unclosed code blocks in output"


def test_no_duplicate_title_in_body(output_content, input_h1):
    """Title should not appear as both frontmatter and H1 in body."""
    assert input_h1 is not None, "Input has no H1 heading"

    match = re.match(r'^---\n.*?\n---\n(.*)$', output_content, re.DOTALL)
    assert match, "Could not extract body"
    body = match.group(1)

    # Count H1 occurrences in body
    h1_count = len(re.findall(r'^# ', body, re.MULTILINE))
    assert h1_count == 0, \
        f"Found {h1_count} H1 heading(s) in body - H1 should only be in frontmatter as title"
