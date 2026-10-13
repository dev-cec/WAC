#!/usr/bin/env python3
"""vmkeys.py — keyboard and mouse of a test VM, for a Windows without guest agent.

A VM whose agent is not installed yet (or does not exist: Windows XP) is driven
as a person would: keys through `virsh send-key`, clicks through the QMP
`input-send-event` of its tablet. The text is typed for the keyboard layout the
VM has — the answer files of create-vm.sh give the French one (AZERTY) to
Windows 7 and later, Windows XP keeps the US one.

Usage:
  vmkeys.py --dom <vm> [--layout fr|us] [--delay s] type '<text>'   (a line feed in the text = Enter;
                                                               never the two characters \\n, which paths contain)
  vmkeys.py --dom <vm> key KEY_LEFTMETA KEY_R             (one chord, Linux key names)
  vmkeys.py --dom <vm> click <x> <y> <width> <height>     (a left click; the screen's size)
"""
import argparse
import json
import subprocess
import sys
import time

VIRSH = ["virsh", "-c", "qemu:///session"]

# What each character costs on the layout: (modifier or None, key).
FR = {"a": (None, "Q"), "q": (None, "A"), "z": (None, "W"), "w": (None, "Z"), "m": (None, "SEMICOLON"),
      " ": (None, "SPACE"), "-": (None, "6"), "&": (None, "1"), '"': (None, "3"), "'": (None, "4"),
      "(": (None, "5"), ")": (None, "MINUS"), "_": (None, "8"), ",": (None, "M"), ";": (None, "COMMA"),
      ":": (None, "DOT"), "=": (None, "EQUAL"), "*": (None, "BACKSLASH"), "<": (None, "102ND"),
      "!": (None, "SLASH"), "$": (None, "RIGHTBRACE"),
      ".": ("LEFTSHIFT", "COMMA"), "/": ("LEFTSHIFT", "DOT"), "?": ("LEFTSHIFT", "M"), ">": ("LEFTSHIFT", "102ND"),
      "%": ("LEFTSHIFT", "APOSTROPHE"),
      "\\": ("RIGHTALT", "8"), "|": ("RIGHTALT", "6"), "@": ("RIGHTALT", "0"), "#": ("RIGHTALT", "3"),
      "{": ("RIGHTALT", "4"), "[": ("RIGHTALT", "5"), "]": ("RIGHTALT", "MINUS"), "}": ("RIGHTALT", "EQUAL")}
US = {" ": (None, "SPACE"), "-": (None, "MINUS"), "=": (None, "EQUAL"), "[": (None, "LEFTBRACE"),
      "]": (None, "RIGHTBRACE"), "\\": (None, "BACKSLASH"), ";": (None, "SEMICOLON"), "'": (None, "APOSTROPHE"),
      ",": (None, "COMMA"), ".": (None, "DOT"), "/": (None, "SLASH"), "`": (None, "GRAVE"),
      "_": ("LEFTSHIFT", "MINUS"), "+": ("LEFTSHIFT", "EQUAL"), "{": ("LEFTSHIFT", "LEFTBRACE"),
      "}": ("LEFTSHIFT", "RIGHTBRACE"), "|": ("LEFTSHIFT", "BACKSLASH"), ":": ("LEFTSHIFT", "SEMICOLON"),
      '"': ("LEFTSHIFT", "APOSTROPHE"), "<": ("LEFTSHIFT", "COMMA"), ">": ("LEFTSHIFT", "DOT"),
      "?": ("LEFTSHIFT", "SLASH"), "!": ("LEFTSHIFT", "1"), "@": ("LEFTSHIFT", "2"), "#": ("LEFTSHIFT", "3"),
      "$": ("LEFTSHIFT", "4"), "%": ("LEFTSHIFT", "5"), "^": ("LEFTSHIFT", "6"), "&": ("LEFTSHIFT", "7"),
      "*": ("LEFTSHIFT", "8"), "(": ("LEFTSHIFT", "9"), ")": ("LEFTSHIFT", "0")}


def chord(layout, character):
    """The keys of one character on a layout."""
    table = FR if layout == "fr" else US
    if character == "\n":
        return ["KEY_ENTER"]
    if character in table:
        modifier, key = table[character]
        return (["KEY_" + modifier] if modifier else []) + ["KEY_" + key]
    if character.isdigit():
        return (["KEY_LEFTSHIFT"] if layout == "fr" else []) + ["KEY_" + character]
    if character.isalpha() and character.isascii():
        key = table.get(character.lower(), (None, character.upper()))[1]
        return (["KEY_LEFTSHIFT"] if character.isupper() else []) + ["KEY_" + key]
    raise SystemExit(f"vmkeys: no key for {character!r} on the {layout} layout")


def send(dom, keys):
    subprocess.run(VIRSH + ["send-key", dom, "--codeset", "linux"] + keys, check=True, stdout=subprocess.DEVNULL)


def click(dom, x, y, width, height):
    def event(events):
        command = json.dumps({"execute": "input-send-event", "arguments": {"events": events}})
        subprocess.run(VIRSH + ["qemu-monitor-command", dom, command], check=True, stdout=subprocess.DEVNULL)
    event([{"type": "abs", "data": {"axis": "x", "value": x * 32767 // width}},
           {"type": "abs", "data": {"axis": "y", "value": y * 32767 // height}}])
    for down in (True, False):
        event([{"type": "btn", "data": {"down": down, "button": "left"}}])


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dom", required=True)
    parser.add_argument("--layout", choices=("fr", "us"), default="fr")
    parser.add_argument("--delay", type=float, default=0.05,
                        help="seconds between two characters; a slow machine (Windows XP) drops keys typed faster than 0.15")
    parser.add_argument("action", choices=("type", "key", "click"))
    parser.add_argument("arguments", nargs="+")
    options = parser.parse_args()
    if options.action == "type":
        for character in options.arguments[0]:
            send(options.dom, chord(options.layout, character))
            time.sleep(options.delay)
    elif options.action == "key":
        send(options.dom, options.arguments)
    else:
        click(options.dom, *(int(a) for a in options.arguments[:4]))


if __name__ == "__main__":
    main()
