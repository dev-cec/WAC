/*! \file
 *  \brief Checks the strict reading of wac.yml: what it accepts, what it
 *  refuses and at which line, and that damaged texts never break it.
 *
 *  WHY THIS TEST. A configuration misread changes what a collection takes,
 *  and nothing shows it. Each construct a configuration does not use must
 *  be refused, with the line at fault; the ones it uses must be read exactly.
 *  Then a valid configuration altered at random (fixed seed) must never make
 *  the reading crash or leave its bounds — built with AddressSanitizer and
 *  UBSan, libyaml included.
 *
 *  Usage: yaml_light_test
 *  Native build (Linux), libyaml's sources beside:
 *    L=../third_party/libyaml-0.2.5
 *    gcc -c -g -fsanitize=address,undefined -DYAML_DECLARE_STATIC -DYAML_VERSION_MAJOR=0 -DYAML_VERSION_MINOR=2 \
 *        -DYAML_VERSION_PATCH=5 '-DYAML_VERSION_STRING="0.2.5"' -I$L/include $L/src/{api,reader,scanner,parser}.c
 *    g++ -std=c++17 -g -fsanitize=address,undefined -DYAML_DECLARE_STATIC -I$L/include -I. \
 *        yaml_light.cpp yaml_light_test.cpp api.o reader.o scanner.o parser.o -o yaml_light_test
 */
#include "yaml_light.h"
#include <cstdio>
#include <random>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! The text must be refused, the message naming `line`.
void refused(const std::string& text, int line, const std::string& what) {
	YamlNode root;
	std::string error;
	const bool read = YamlParse(text, root, error);
	check(!read, what + ": accepted");
	check(read || error.compare(0, 5 + std::to_string(line).size(), "line " + std::to_string(line)) == 0,
	      what + ": refused as \"" + error + "\", line " + std::to_string(line) + " expected");
}

} // namespace

int main() {
	const std::string sample =
		"\xEF\xBB\xBF# WAC configuration\n"
		"convert: false        # collection only\n"
		"binary: unverified\n"
		"output: \"D:\\\\cases\\\\2026-042\"\n"
		"artefacts:\n"
		"  registry: true\n"
		"  events: 'yes, all'\n"
		"\n"
		"  prefetch: false\n";
	YamlNode root;
	std::string error;
	check(YamlParse(sample, root, error), "sample refused: " + error);
	const YamlNode* convert = root.child("convert");
	check(convert && !convert->mapping && convert->scalar == "false" && convert->line == 2, "convert read wrong");
	check(root.child("binary") && root.child("binary")->scalar == "unverified", "binary read wrong");
	check(root.child("output") && root.child("output")->scalar == "D:\\cases\\2026-042", "double-quoted escapes read wrong");
	const YamlNode* artefacts = root.child("artefacts");
	check(artefacts && artefacts->mapping && artefacts->children.size() == 3, "nested mapping read wrong");
	check(artefacts && artefacts->child("events") && artefacts->child("events")->scalar == "yes, all", "single-quoted value read wrong");
	check(artefacts && artefacts->child("prefetch") && artefacts->child("prefetch")->line == 9, "line numbers wrong");
	check(root.children.size() == 4 && root.children[0].first == "convert" && root.children[3].first == "artefacts",
	      "order of the keys not kept");

	YamlNode empty;
	check(YamlParse("# nothing but a comment\n\n", empty, error) && empty.mapping && empty.children.empty(),
	      "a file of comments is an empty configuration");
	check(YamlParse("", empty, error) && empty.children.empty(), "an empty file is an empty configuration");

	refused("binary: all\nbinary: none\n", 2, "duplicate key");
	refused("artefacts:\n  events: true\n  events: false\n", 3, "duplicate nested key");
	refused("artefacts:\n  - registry\n", 2, "a list");
	refused("a: &x 1\nb: *x\n", 1, "an anchor");
	refused("binary: !!str all\n", 1, "a tag");
	refused("binary: all\n---\nbinary: none\n", 2, "a second document");
	refused("artefacts:\n\tregistry: true\n", 2, "a tab as indentation");
	refused("output: \"unclosed\n", 1, "a quote left open");
	refused("just a sentence\n", 1, "a file that is not a mapping");
	refused("a:\n b:\n  c:\n   d:\n    e:\n     f:\n      g:\n       h:\n        i: 1\n", 9, "nested too deep");

	// Damaged texts: within bounds, whatever the verdict.
	std::mt19937_64 rng(20260926);
	for (int round = 0; round < 3000; ++round) {
		std::string damaged = sample;
		const int edits = 1 + (int)(rng() % 5);
		for (int k = 0; k < edits; ++k) damaged[rng() % damaged.size()] = (char)(rng() % 128);
		if (rng() % 4 == 0) damaged.resize(rng() % damaged.size());
		YamlNode r;
		YamlParse(damaged, r, error);
		++g_checks;
	}
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
