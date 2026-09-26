# libyaml 0.2.5 — copied into WAC

- Origin: https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz
- SHA-256 of that archive: `c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4`
  (the value Linux distributions and Homebrew record for this release).
- Licence: MIT (`License`, kept as distributed).
- Files kept, UNMODIFIED: `include/yaml.h`, `src/api.c`, `src/reader.c`,
  `src/scanner.c`, `src/parser.c`, `src/yaml_private.h` — the parser only.
  The emitter, the dumper and the loader are left out: WAC reads YAML, it
  never writes it, and code not built is code not to review.

## Why a dependency

WAC reads its configuration from `wac.yml` (decision of 2026-09-26). The
configuration decides what a collection takes: its reading must be exact
and must refuse what it does not understand. libyaml is the reference
implementation of YAML (PyYAML's), small, long exercised. WAC uses its
event interface (`yaml_light.cpp`), which also lets it refuse a duplicate
key — a second value would otherwise silently override the first — and
anything but mappings of plain scalars.

## Build

Compiled into WAC.exe by `build-windows.sh`, as C, with
`YAML_DECLARE_STATIC` and the version macros autotools would otherwise put
in `config.h`. To update: replace these files from a new release, record its
archive's SHA-256 here, rebuild, rerun `yaml_light_test`.
