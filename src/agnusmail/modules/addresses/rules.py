"""Rules for the local part of ``name@service-domain`` addresses.

Pure functions: syntax, the canonical form used for uniqueness, and reserved names.
"""

import re

MIN_LENGTH = 3
MAX_LENGTH = 32
# Letters/digits at both ends; '.', '-', '_' inside, never two in a row.
LOCAL_PART = re.compile(r"^[a-z0-9](?:[a-z0-9]|[._-](?=[a-z0-9]))*$")
PUNCTUATION = re.compile(r"[._-]")
# Applied in order, multi-character sequences first.
CONFUSABLES: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "l"),
    ("i", "l"),
)
# RFC 2142 role mailboxes plus operational names. Compared by canonical form.
RESERVED_NAMES = frozenset(
    {
        "abuse",
        "admin",
        "administrator",
        "api",
        "billing",
        "contact",
        "dkim",
        "dmarc",
        "ftp",
        "help",
        "hostmaster",
        "imap",
        "info",
        "legal",
        "mail",
        "mailerdaemon",
        "marketing",
        "news",
        "noc",
        "noreply",
        "null",
        "official",
        "pop",
        "postmaster",
        "privacy",
        "root",
        "sales",
        "security",
        "smtp",
        "staff",
        "support",
        "system",
        "team",
        "undefined",
        "usenet",
        "uucp",
        "webmaster",
        "www",
    }
)
RESERVED_PREFIXES = ("agnus",)


class InvalidLocalPartError(ValueError):
    pass


class ReservedLocalPartError(ValueError):
    pass


def canonical(local_part: str) -> str:
    """Uniqueness key: punctuation removed, ASCII confusables unified."""
    value = PUNCTUATION.sub("", local_part.lower())
    for source, target in CONFUSABLES:
        value = value.replace(source, target)
    return value


def _reserved_forms() -> frozenset[str]:
    return frozenset(canonical(name) for name in RESERVED_NAMES)


RESERVED_CANONICAL = _reserved_forms()
RESERVED_CANONICAL_PREFIXES = tuple(canonical(prefix) for prefix in RESERVED_PREFIXES)


def normalize(local_part: str) -> str:
    """Validate and lowercase a requested local part; raises on any violation."""
    if not local_part.isascii():
        raise InvalidLocalPartError("only ASCII letters, digits, '.', '-' and '_'")
    value = local_part.lower()
    if not MIN_LENGTH <= len(value) <= MAX_LENGTH:
        raise InvalidLocalPartError(f"length must be {MIN_LENGTH}-{MAX_LENGTH}")
    if not LOCAL_PART.fullmatch(value):
        raise InvalidLocalPartError(
            "use letters, digits, '.', '-' or '_'; start and end with a letter or digit; "
            "no two punctuation marks in a row"
        )
    return value


def check_not_reserved(local_part: str) -> None:
    form = canonical(local_part)
    if form in RESERVED_CANONICAL or form.startswith(RESERVED_CANONICAL_PREFIXES):
        raise ReservedLocalPartError("this name is reserved")
