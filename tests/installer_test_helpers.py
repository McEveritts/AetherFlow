"""Load production shell helpers without sourcing host paths or credentials."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def common_functions(*names):
    source = (ROOT / "packages/common.sh").read_text()
    functions = []
    for name in names:
        start = source.index(f"\n{name}() ") + 1
        opening = source[start:source.index("\n", start)]
        ending = "\n)\n" if opening.endswith("(") else "\n}\n"
        end = source.index(ending, start) + len(ending)
        functions.append(source[start:end])
    return "\n".join(functions)


def replace_paths_once(source, replacements):
    """Rebase fixture paths once, even when TMPDIR itself contains /home/."""
    import re
    mapping = dict(replacements)
    pattern = re.compile("|".join(re.escape(path) for path in sorted(mapping, key=len, reverse=True)))
    return pattern.sub(lambda match: mapping[match.group(0)], source)
