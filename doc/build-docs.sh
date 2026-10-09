#!/usr/bin/env bash
# build-docs.sh — builds the PDF of every WAC document (or of those named),
# with the command of the editor's recipe (LaTeX Workshop, "latexmk
# (lualatex)"), then removes the build artefacts the editor's clean step
# removes: only the .tex and the .pdf stay beside each other.
#
# LuaLaTeX, not XeLaTeX: wac-style.tex breaks long monospace names through a
# Lua filter (a XeTeX fallback remains), and a document that builds here
# builds in the editor.
#
# Usage: doc/build-docs.sh [file.tex ...]   (default: every *_FR.tex and *_EN.tex of doc/)
# Exit code: 0 if every document built without an overfull line, 1 otherwise.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -gt 0 ]]; then documents=("$@"); else mapfile -t documents < <(ls "$HERE"/*/*_FR.tex "$HERE"/*/*_EN.tex); fi

status=0
for tex in "${documents[@]}"; do
  folder="$(cd "$(dirname "$tex")" && pwd)"; name="$(basename "$tex" .tex)"
  if ( cd "$folder" && latexmk -synctex=1 -interaction=nonstopmode -file-line-error -lualatex -shell-escape "$name.tex" >/dev/null 2>&1 ); then
    overfull=$(grep -c 'Overfull \\hbox' "$folder/$name.log" || true)
    echo "$name.pdf  ($overfull overfull line(s))"
    [[ "$overfull" == "0" ]] || status=1
  else
    echo "$name: FAILED — $(grep -m1 -E '^.*:[0-9]+: |^!' "$folder/$name.log")"
    status=1
  fi
  # The editor's clean list (latex-workshop.latex.clean.fileTypes), and the .xdv of a XeLaTeX build.
  for ext in aux bbl blg idx ind lof lot out toc fls log fdb_latexmk snm nav vrb synctex.gz "synctex(busy)" "synctex.gz(busy)" markdown.in xdv; do
    rm -f "$folder/$name.$ext"
  done
  rm -rf "$folder"/_markdown_"$name"*
done
exit $status
