/*! \file
 *  \brief Confronts WAC's authenticity verification with Windows's own.
 *
 *  Usage:
 *    authenticode_test --catalogs `<folder>`
 *        verifies and indexes every .cat of the folder, and summarises it;
 *    authenticode_test --catalogs `<folder>` --files `<list>`
 *        then returns a verdict per file. `<list>`: one line per file,
 *        "identifier|local path". Output: "identifier|MICROSOFT|source" or
 *        "identifier|COLLECT|reason".
 *    authenticode_test --rsa `<modulus hex>` `<exponent hex>` `<signature hex>` `<sha256 hex>`
 *        verifies an isolated RSA signature (confronted with OpenSSL).
 *
 *  The judge is Get-AuthenticodeSignature, run in the VM on the same files (see
 *  vmtest/README.md). This program reads the files through the API: it is a test
 *  tool, not the collection.
 *
 *  Build (Linux):
 *    g++ -std=c++17 -O2 -I. authenticode.cpp rsa.cpp sha.cpp authenticode_test.cpp
 */
#include "authenticode.h"
#include "rsa.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <map>
#include <sstream>
#include <vector>
#include <chrono>

namespace {

std::vector<uint8_t> read(const std::filesystem::path& p) {
	std::ifstream f(p, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

std::vector<uint8_t> hex(const std::string& h) {
	std::vector<uint8_t> r;
	for (size_t i = 0; i + 1 < h.size(); i += 2) r.push_back((uint8_t)std::stoi(h.substr(i, 2), nullptr, 16));
	return r;
}

std::string utf8(const std::wstring& w) {
	std::string r;
	for (wchar_t c : w) {
		if (c < 0x80) r += (char)c;
		else if (c < 0x800) { r += (char)(0xC0 | (c >> 6)); r += (char)(0x80 | (c & 0x3F)); }
		else { r += (char)(0xE0 | (c >> 12)); r += (char)(0x80 | ((c >> 6) & 0x3F)); r += (char)(0x80 | (c & 0x3F)); }
	}
	return r;
}

} // namespace

/*! Runs the test.
 * @param argc,argv see the file header for the arguments
 * @return 0 if every check passed */
int main(int argc, char** argv) {
	if (argc == 6 && std::strcmp(argv[1], "--rsa") == 0) {
		const auto n = hex(argv[2]), e = hex(argv[3]), s = hex(argv[4]), h = hex(argv[5]);
		const bool ok = RsaVerifyPkcs1(n.data(), n.size(), e.data(), e.size(), s.data(), s.size(),
		                                 DigestAlgorithm::Sha256, h.data(), h.size());
		std::cout << (ok ? "VALID" : "INVALID") << "\n";
		return ok ? 0 : 1;
	}
	std::string folder, list;
	for (int i = 1; i + 1 < argc; i += 2) {
		if (std::strcmp(argv[i], "--catalogs") == 0) folder = argv[i + 1];
		else if (std::strcmp(argv[i], "--files") == 0) list = argv[i + 1];
	}
	if (folder.empty()) { std::cerr << "usage: see the header of the file\n"; return 2; }

	IndexCatalogues index;
	std::map<std::string, size_t> refusals;
	size_t read = 0;
	const auto t0 = std::chrono::steady_clock::now();
	for (const auto& e : std::filesystem::directory_iterator(folder)) {
		if (e.path().extension() != ".cat") continue;
		const std::vector<uint8_t> d = read(e.path());
		++read;
		if (!index.add(e.path().filename().wstring(), d.data(), d.size())) {
			const VerifiedSignature s = VerifyPkcs7(d.data(), d.size());
			++refusals[s.valid ? (s.signerAccepted ? std::string("no indexable digest")
			                                         : "signer not accepted: " + utf8(s.signer))
			                 : s.reason];
		}
	}
	const double duration = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
	std::cerr << read << " catalog(s) read, " << index.catalogues() << " kept, "
	          << index.fingerprints() << " digest(s) indexed, in " << duration << " s\n";
	for (const auto& r : refusals) std::cerr << "  refusés : " << r.second << " — " << r.first << "\n";

	if (list == "-") {                                 // indexed digests, in hexadecimal
		index.dump(std::cout);
		return 0;
	}
	if (list.empty()) return 0;
	std::ifstream l(list);
	std::string line;
	size_t ms = 0, others = 0;
	while (std::getline(l, line)) {
		if (!line.empty() && line.back() == '\r') line.pop_back();
		const size_t bar = line.find('|');
		if (bar == std::string::npos) continue;
		const std::string id = line.substr(0, bar);
		std::ifstream f(std::filesystem::u8path(line.substr(bar + 1)), std::ios::binary);
		if (!f) { std::cout << id << "|UNREADABLE|\n"; continue; }
		const std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		PeAnalyser pe;
		pe.sputn((const char*)bytes.data(), (std::streamsize)bytes.size());
		pe.finish();
		VerdictMicrosoft v;
		if (pe.isPe()) v = EvaluatePe(pe, index);
		else {
			// A script or a document: the catalog (raw bytes), then the embedded
			// PowerShell signature.
			uint8_t h[32];
			sha256Bytes(bytes.data(), bytes.size(), h);
			v = EvaluateByCatalog(h, index);
			if (!v.microsoft) {
				const VerdictMicrosoft ps = EvaluatePowerShellScript(bytes.data(), bytes.size());
				if (ps.microsoft || ps.reason != "no embedded signature") v = ps;
			}
		}
		if (v.microsoft) { ++ms; std::cout << id << "|MICROSOFT|" << utf8(v.source) << "\n"; }
		else { ++others; std::cout << id << "|COLLECT|" << v.reason << "\n"; }
	}
	std::cerr << ms << " authenticated as Microsoft, " << others << " to collect\n";
	return 0;
}
