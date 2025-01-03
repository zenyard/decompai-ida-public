"""
Minimal formatting for markdown.
"""

import re
from textwrap import wrap

_WIDTH = 80
_INDENT_PATTERN = re.compile(r"^(\s*(?:[-+*]\s+)?)(.*)$")


def format(text: str) -> str:
    lines = text.split("\n")
    output_lines = list[str]()

    for line in lines:
        indent_match = _INDENT_PATTERN.match(line)
        assert indent_match is not None

        initial_indent = indent_match.group(1)
        assert isinstance(initial_indent, str)

        body = indent_match.group(2)
        assert isinstance(body, str)

        wrapped_lines = wrap(
            body,
            width=_WIDTH,
            initial_indent=initial_indent,
            subsequent_indent=" " * len(initial_indent),
        )

        output_lines.extend(wrapped_lines if len(wrapped_lines) > 0 else [""])

    return "\n".join(output_lines)
