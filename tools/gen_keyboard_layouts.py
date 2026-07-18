"""Generate virtual_fido/keyboard_layouts.py from the system xkb database.

Parses /usr/share/X11/xkb/symbols/* sections (resolving includes), maps xkb
key names to USB HID usage codes, and inverts each layout into a
char -> (usage, modifier) table covering printable ASCII. Dead keys and
non-ASCII symbols are dropped — OTP/static-password typing only needs ASCII.

Run from python/:  uv run python tools/gen_keyboard_layouts.py
"""

from __future__ import annotations

import re
from pathlib import Path

XKB_DIR = Path("/usr/share/X11/xkb/symbols")
OUT = Path(__file__).resolve().parent.parent / "virtual_fido" / "keyboard_layouts.py"

# name -> (xkb file, xkb section)
LAYOUTS = {
    "qwerty": ("us", "basic"),
    "qwertz": ("de", "basic"),
    "azerty": ("fr", "basic"),
    "dvorak": ("us", "dvorak"),
    "colemak": ("us", "colemak"),
    "colemak-dh": ("us", "colemak_dh"),
    "colemak-dh-iso": ("us", "colemak_dh_iso"),
}

MOD_SHIFT = 0x02
MOD_ALTGR = 0x40  # right alt

# xkb key name -> HID usage (USB HID Usage Tables ch. 10, positions named
# after their US-QWERTY legends).
HID_USAGE = {
    "TLDE": 0x35,
    **{f"AE{i:02d}": 0x1E + i - 1 for i in range(1, 11)},  # digit row 1..0
    "AE11": 0x2D, "AE12": 0x2E,
    "AD01": 0x14, "AD02": 0x1A, "AD03": 0x08, "AD04": 0x15, "AD05": 0x17,
    "AD06": 0x1C, "AD07": 0x18, "AD08": 0x0C, "AD09": 0x12, "AD10": 0x13,
    "AD11": 0x2F, "AD12": 0x30, "BKSL": 0x31,
    "AC01": 0x04, "AC02": 0x16, "AC03": 0x07, "AC04": 0x09, "AC05": 0x0A,
    "AC06": 0x0B, "AC07": 0x0D, "AC08": 0x0E, "AC09": 0x0F,
    "AC10": 0x33, "AC11": 0x34,
    "AB01": 0x1D, "AB02": 0x1B, "AB03": 0x06, "AB04": 0x19, "AB05": 0x05,
    "AB06": 0x11, "AB07": 0x10,
    "AB08": 0x36, "AB09": 0x37, "AB10": 0x38,
    "LSGT": 0x64,  # ISO key between left shift and Z; absent on ANSI boards
    "SPCE": 0x2C,
}

# keysym name -> ASCII char, for the non-letter/digit names that occur in the
# layouts above. Anything not resolvable to printable ASCII becomes None.
KEYSYMS = {
    "space": " ",
    "exclam": "!", "quotedbl": '"', "numbersign": "#", "dollar": "$",
    "percent": "%", "ampersand": "&", "apostrophe": "'", "parenleft": "(",
    "parenright": ")", "asterisk": "*", "plus": "+", "comma": ",",
    "minus": "-", "period": ".", "slash": "/", "colon": ":",
    "semicolon": ";", "less": "<", "equal": "=", "greater": ">",
    "question": "?", "at": "@", "bracketleft": "[", "backslash": "\\",
    "bracketright": "]", "asciicircum": "^", "underscore": "_",
    "grave": "`", "braceleft": "{", "bar": "|", "braceright": "}",
    "asciitilde": "~",
}


def keysym_to_char(name: str) -> str | None:
    if len(name) == 1 and name.isascii() and name.isprintable():
        return name
    return KEYSYMS.get(name)


_SECTION_RE = re.compile(r'xkb_symbols\s+"([^"]+)"\s*\{')
_KEY_RE = re.compile(r"key\s*<([A-Z0-9]+)>\s*\{(.*?)\}\s*;", re.S)
_INCLUDE_RE = re.compile(r'include\s+"([^"]+)"')
_SYMS_RE = re.compile(r"\[([^\]]*)\]")


def read_section(file: str, section: str) -> str:
    text = (XKB_DIR / file).read_text()
    for m in _SECTION_RE.finditer(text):
        if m.group(1) == section:
            depth, i = 1, m.end()
            while depth:
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                i += 1
            return text[m.end() : i - 1]
    raise KeyError(f"{file}({section}) not found")


def parse_section(file: str, section: str, keys: dict[str, list[str]]) -> None:
    """Populate keys[xkb_name] = [level1, level2, level3, ...] keysym names,
    recursing into includes first so later definitions override."""
    body = read_section(file, section)
    for m in _INCLUDE_RE.finditer(body):
        ref = m.group(1)
        if ref.startswith("level3"):  # modifier wiring, no symbols
            continue
        if "(" in ref:
            inc_file, inc_section = ref.rstrip(")").split("(")
        else:
            inc_file, inc_section = ref, "basic"
        parse_section(inc_file, inc_section, keys)
    for m in _KEY_RE.finditer(body):
        name, keybody = m.group(1), m.group(2)
        syms = _SYMS_RE.search(keybody)
        if not syms:
            continue
        keys[name] = [s.strip() for s in syms.group(1).split(",")]


def build_table(file: str, section: str) -> dict[str, tuple[int, int]]:
    keys: dict[str, list[str]] = {}
    parse_section(file, section, keys)
    table: dict[str, tuple[int, int]] = {}
    # (level index, modifier bits); lower levels win on conflicts
    levels = [(0, 0), (1, MOD_SHIFT), (2, MOD_ALTGR), (3, MOD_SHIFT | MOD_ALTGR)]
    # Sort so plain keys are visited before LSGT (absent on ANSI keyboards):
    # if a char appears on both, prefer the universally-present position.
    for name in sorted(keys, key=lambda n: (HID_USAGE.get(n, 0) == 0x64, n)):
        usage = HID_USAGE.get(name)
        if usage is None:
            continue
        syms = keys[name]
        for lvl, mods in levels:
            if lvl >= len(syms):
                break
            char = keysym_to_char(syms[lvl])
            if char is not None and char not in table:
                table[char] = (usage, mods)
    table["\n"] = (0x28, 0)  # Enter
    table["\t"] = (0x2B, 0)  # Tab
    # Most symbols files inherit SPCE from xkb defaults rather than define it.
    table.setdefault(" ", (0x2C, 0))
    return table


def main() -> None:
    lines = [
        '"""Keyboard layout tables: char -> (HID usage, modifier bits).',
        "",
        "GENERATED by tools/gen_keyboard_layouts.py from the xkb database —",
        "edit and re-run that script instead of editing this file.",
        '"""',
        "",
        "MOD_SHIFT = 0x02",
        "MOD_ALTGR = 0x40  # right alt (AltGr)",
        "",
        "LAYOUTS: dict[str, dict[str, tuple[int, int]]] = {",
    ]
    for layout, (file, section) in LAYOUTS.items():
        table = build_table(file, section)
        lines.append(f'    # {file}({section})')
        lines.append(f'    "{layout}": {{')
        for char, (usage, mods) in sorted(table.items()):
            lines.append(f"        {char!r}: (0x{usage:02X}, 0x{mods:02X}),")
        lines.append("    },")
    lines.append("}")
    lines.append("")
    OUT.write_text("\n".join(lines))
    print(f"Wrote {OUT}")
    for layout in LAYOUTS:
        table = build_table(*LAYOUTS[layout])
        missing = [c for c in "cbdefghijklnrtuv0123456789" if c not in table]
        assert not missing, f"{layout} missing ModHex/digits: {missing}"
        print(f"  {layout}: {len(table)} chars")


if __name__ == "__main__":
    main()
