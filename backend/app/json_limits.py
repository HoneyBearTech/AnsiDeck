"""JSON from untrusted places (an inventory plugin's output) parsed without letting its
nesting drive the parser's recursion: deep input is refused after a linear scan, before
json.loads would recurse into it (slow or worse on some Python builds and tracers)."""

import json
import re
from itertools import accumulate
from typing import Any

_STRINGS = re.compile(rb'"(?:[^"\\]|\\.)*"', re.DOTALL)
_NOT_BRACKETS = bytes(b for b in range(256) if b not in b"[]{}")
_DELTA = {ord("["): 1, ord("{"): 1, ord("]"): -1, ord("}"): -1}


class TooDeep(ValueError):
    pass


def nesting_depth(raw: bytes) -> int:
    """How deeply arrays and objects nest in `raw` (brackets inside strings don't count)."""
    brackets = _STRINGS.sub(b"", raw).translate(None, delete=_NOT_BRACKETS)
    return max(accumulate(_DELTA[b] for b in brackets), default=0)


def loads_bounded(raw: bytes | str, max_depth: int) -> Any:
    """json.loads, refusing (TooDeep) anything nested deeper than max_depth."""
    data = raw.encode() if isinstance(raw, str) else raw
    if nesting_depth(data) > max_depth:
        raise TooDeep(f"nested deeper than {max_depth} levels")
    return json.loads(data)
