/*! \file
 *  \brief Checks the JSON reader (Json::parse) against the JSON writer.
 *
 *  WHY THIS TEST. --convert reads back what --collect wrote: the exhibit
 *  manifest, whose fingerprints decide whether the evidence is still intact,
 *  and the snapshot of the live state. A reader that loses or alters a value
 *  would make a conversion wrong without an error; one that accepts a
 *  malformed text would convert a damaged snapshot. Checked:
 *    - every value the writer produces reads back identical (dump, parse,
 *      dump again: the same text);
 *    - the real output of a collection, given as arguments, reads back and
 *      rewrites to the same text;
 *    - malformed texts are refused (trailing comma, unquoted key, leading
 *      zero, control character, bad escape, excessive nesting, text after the
 *      value…);
 *    - random mutations of valid texts never make the reader crash or read
 *      out of bounds — built with AddressSanitizer and UBSan.
 *
 *  Build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. json_test.cpp -o json_test
 *  Usage: json_test [file.json ...]
 */
#include "json.h"
#include <cstdio>
#include <fstream>
#include <random>
#include <sstream>
#include <string>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! UTF-8 -> wide string (the files WAC writes are UTF-8 without a BOM).
std::wstring fromUtf8(const std::string& s) {
	std::wstring out;
	for (size_t i = 0; i < s.size();) {
		const unsigned char c = (unsigned char)s[i];
		unsigned cp = c, n = 0;
		if (c >= 0xF0) { cp = c & 0x07; n = 3; }
		else if (c >= 0xE0) { cp = c & 0x0F; n = 2; }
		else if (c >= 0xC0) { cp = c & 0x1F; n = 1; }
		++i;
		for (unsigned k = 0; k < n && i < s.size(); ++k, ++i) cp = (cp << 6) | ((unsigned char)s[i] & 0x3F);
		out += (wchar_t)cp;
	}
	return out;
}

std::string narrow(const std::wstring& w) { return std::string(w.begin(), w.end()); }

void roundTrip() {
	Json o = Json::obj();
	o.add(L"Text", Json::str(L"quote \" backslash \\ tab \t newline \n control \x01 é €"));
	o.add(L"Path", Json::str(L"C:\\Windows\\System32\\config\\SYSTEM"));
	o.add(L"Zero", Json::num(0));
	o.add(L"Negative", Json::num(-42));
	o.add(L"Big", Json::num(18446744073709551615ULL));
	o.add(L"True", Json::boolean(true));
	o.add(L"False", Json::boolean(false));
	Json a = Json::arr();
	a.push(Json::str(L"x")).push(Json::obj()).push(Json::arr()).push(Json::num(7));
	Json inner = Json::obj();
	inner.add(L"Deep", Json::arr().push(Json::arr().push(Json::str(L"y"))));
	a.push(std::move(inner));
	o.add(L"List", std::move(a));
	const std::wstring text = o.dump(0);
	Json back = Json::null();
	std::wstring error;
	check(Json::parse(text, back, error), "round trip: parse refused: " + narrow(error));
	check(back.dump(0) == text, "round trip: the text read back differs");
	check(back.find(L"Path") && back.find(L"Path")->text() == L"C:\\Windows\\System32\\config\\SYSTEM",
	      "round trip: a raw path is not restored");
	check(back.find(L"Big") && back.find(L"Big")->text() == L"18446744073709551615", "round trip: a 64-bit number is altered");
}

void realFile(const char* path) {
	std::ifstream f(path, std::ios::binary);
	std::stringstream ss;
	ss << f.rdbuf();
	std::string raw = ss.str();
	std::string lf;
	for (char c : raw) if (c != '\r') lf += c;          // written in text mode on Windows: CRLF
	const std::wstring text = fromUtf8(lf);
	Json v = Json::null();
	std::wstring error;
	const bool ok = Json::parse(text, v, error);
	check(ok, std::string(path) + ": refused: " + narrow(error));
	// The files written whole by writeJsonFile (not the streamed events.json) rewrite identically.
	if (ok && std::string(path).find("events.json") == std::string::npos)
		check(v.dump(0) == text, std::string(path) + ": rewritten differently");
}

void malformed() {
	const wchar_t* bad[] = {
		L"", L" ", L"{", L"}", L"[1,]", L"{\"a\":1,}", L"{a:1}", L"{\"a\" 1}", L"[01]", L"[1.]",
		L"[.5]", L"[1e]", L"[-]", L"[\"\\x\"]", L"[\"\\u12\"]", L"[\"a\x01\"]", L"[\"unterminated]",
		L"tru", L"nul", L"[true false]", L"{} {}", L"[1] x", L"[\"a\"", L"{\"a\":}", L"[,1]",
	};
	for (const wchar_t* b : bad) {
		Json v = Json::null();
		std::wstring error;
		check(!Json::parse(b, v, error), "malformed text accepted: " + narrow(b));
	}
	std::wstring deep(65, L'['), close(65, L']');
	Json v = Json::null();
	std::wstring error;
	check(!Json::parse(deep + close, v, error), "nesting of 65 accepted");
	std::wstring ok(64, L'['), okClose(64, L']');
	check(Json::parse(ok + okClose, v, error), "nesting of 64 refused");
}

void mutations() {
	Json o = Json::obj();
	o.add(L"Items", Json::arr().push(Json::str(L"a\\b")).push(Json::num(12)).push(Json::boolean(true)));
	o.add(L"Name", Json::str(L"x"));
	const std::wstring base = o.dump(1);
	std::mt19937_64 rng(20260925);
	const wchar_t alphabet[] = L"{}[]\",:\\ 0123456789-.eEtrufalsn\x01u";
	for (int n = 0; n < 200000; ++n) {
		std::wstring t = base;
		const int edits = 1 + (int)(rng() % 4);
		for (int k = 0; k < edits; ++k) {
			const size_t at = rng() % (t.size() + 1);
			switch (rng() % 3) {
			case 0: if (at < t.size()) t[at] = alphabet[rng() % (sizeof(alphabet) / sizeof(*alphabet) - 1)]; break;
			case 1: if (at < t.size()) t.erase(at, 1); break;
			default: t.insert(at, 1, alphabet[rng() % (sizeof(alphabet) / sizeof(*alphabet) - 1)]);
			}
		}
		if (rng() % 5 == 0) t.resize(rng() % (t.size() + 1));   // truncations
		Json v = Json::null();
		std::wstring error;
		if (Json::parse(t, v, error)) {
			// What is accepted must be JSON the writer rewrites and the reader accepts again.
			Json again = Json::null();
			check(Json::parse(v.dump(0), again, error) && again.dump(0) == v.dump(0), "accepted mutation not stable");
		}
	}
	++g_checks;
}

} // namespace

/*! Runs every check.
 * @param argc,argv files of a real collection to read back
 * @return 0 if all passed */
int main(int argc, char** argv) {
	roundTrip();
	malformed();
	mutations();
	for (int i = 1; i < argc; ++i) realFile(argv[i]);
	std::printf("%s: %llu check(s), %llu failure(s)\n", g_failures ? "FAILED" : "all passed", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
