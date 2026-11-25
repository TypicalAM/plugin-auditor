"""Tags scan hits that sit in plain documentation with a `doc:` prefix.

Used by the scan_*.sh helpers, never run on its own. A hit in documentation is
context (pattern catalogues, changelogs, READMEs), not code that runs, but it is
still reported so the sub-agent can read it and promote it when the doc tells a
user or agent to run it.

Documentation = markdown-family file that is NOT an instruction file the agent
loads: SKILL.md, CLAUDE.md, AGENTS.md, GEMINI.md, anything under agents/,
commands/, hooks/, output-styles/, .claude/, and any markdown whose YAML
frontmatter has both name: and description:.

Modes (stdin to stdout):
  lines  <path>:<rest>            becomes doc:<path>:<rest> for doc paths
  host   <host>\t<path:line>\t<raw> becomes doc:<host>\t... for doc paths
"""

import os
import re
import sys

DOC_EXT = {".md", ".mdx", ".markdown", ".rst", ".adoc"}
INSTRUCTION_NAMES = {"SKILL.md", "CLAUDE.md", "AGENTS.md", "GEMINI.md"}
INSTRUCTION_DIRS = {"agents", "commands", "hooks", "output-styles", ".claude"}
_cache = {}


def has_artifact_frontmatter(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(4096)
    except OSError:
        return False
    m = re.match(r"\A\ufeff?---\s*\n(.*?)\n---\s*(\n|\Z)", head, re.S)
    if not m:
        return False
    fm = m.group(1)
    return bool(re.search(r"^name\s*:", fm, re.M) and re.search(r"^description\s*:", fm, re.M))


def is_doc(path):
    if path in _cache:
        return _cache[path]
    base = os.path.basename(path)
    parts = set(path.replace("\\", "/").split("/")[:-1])
    doc = (
        os.path.splitext(base)[1].lower() in DOC_EXT
        and base not in INSTRUCTION_NAMES
        and not (parts & INSTRUCTION_DIRS)
        and not has_artifact_frontmatter(path)
    )
    _cache[path] = doc
    return doc


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "lines"
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        if mode == "host":
            host, loc, *rest = line.split("\t")
            path = loc.rsplit(":", 1)[0]
            if is_doc(path) and not host.startswith("local:"):
                host = "doc:" + host
            print("\t".join([host, loc, *rest]))
        else:
            path = line.split(":", 1)[0]
            print(("doc:" + line) if is_doc(path) else line)


main()
