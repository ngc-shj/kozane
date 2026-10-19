"""Parser for policy/waivers.toml (M3 plan, Law amendments: Packaging).

Shared by tools/check-pins (P6) and tools/package. Both import it from the
tools/ directory:

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import waivers

`load(path)` returns the waivers in file order and raises `WaiverError` for
a missing or unreadable file, invalid TOML, or anything outside the schema
(unknown keys, a missing or non-string field, a status other than
"open"/"closed", a duplicate id). Callers treat `WaiverError` as refuse.
"""

import pathlib
import tomllib
from typing import NamedTuple

STATUSES = ("open", "closed")
FIELDS = ("id", "owner", "status")


class WaiverError(Exception):
    pass


class Waiver(NamedTuple):
    id: str
    owner: str
    status: str


def parse(text: str) -> list:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise WaiverError(f"not valid TOML: {e}") from None
    if set(data) - {"waivers"}:
        raise WaiverError(f"unknown top-level keys: {sorted(set(data) - {'waivers'})}")
    entries = data.get("waivers", [])
    if not isinstance(entries, list):
        raise WaiverError("'waivers' must be an array of tables ([[waivers]])")
    out, seen = [], set()
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or set(e) != set(FIELDS):
            raise WaiverError(f"waiver {i} must have exactly the keys {', '.join(FIELDS)}")
        if not all(isinstance(e[k], str) and e[k] for k in FIELDS):
            raise WaiverError(f"waiver {i}: every field must be a non-empty string")
        if e["status"] not in STATUSES:
            raise WaiverError(f"waiver {e['id']}: status {e['status']!r} is not one of {', '.join(STATUSES)}")
        if e["id"] in seen:
            raise WaiverError(f"waiver {e['id']} is listed twice")
        seen.add(e["id"])
        out.append(Waiver(e["id"], e["owner"], e["status"]))
    return out


def load(path: pathlib.Path) -> list:
    try:
        text = pathlib.Path(path).read_text()
    except (OSError, UnicodeDecodeError) as e:
        raise WaiverError(f"cannot read {path}: {e}") from None
    return parse(text)


def open_waivers(waivers: list) -> list:
    return [w for w in waivers if w.status == "open"]
