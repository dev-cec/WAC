/*! \file
 *  \brief Checks the WMI repository reader: a class, its ancestor and an
 *  instance built as the format lays them out, hostile variants, the name
 *  hash against a key of a real repository — and, given a repository
 *  folder, the subscriptions it holds.
 *
 *  WHY THIS TEST. A class read one byte off still gives names and values —
 *  wrong ones: every value is found through offsets. Each case here has a
 *  known result; the hostile ones (a count that lies, a record cut short)
 *  must be refused, never read beyond the bytes given.
 *
 *  Usage (runs under wine): cim_test.exe [Repository folder]
 */
#include "cim_repository.h"
#include "wmi_persistence.h"
#include <cstdio>

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const char* what) {
	++g_checks;
	if (!ok && ++g_failures <= 30) std::printf("  FAILED  %s\n", what);
}

void put32(std::vector<uint8_t>& b, uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(v >> (8 * i))); }
void put16(std::vector<uint8_t>& b, uint16_t v) { b.push_back((uint8_t)v); b.push_back((uint8_t)(v >> 8)); }
//! A heap string of one byte per character; @return its offset.
uint32_t ascii(std::vector<uint8_t>& heap, const std::string& s) {
	const uint32_t at = (uint32_t)heap.size();
	heap.push_back(0);
	heap.insert(heap.end(), s.begin(), s.end());
	heap.push_back(0);
	return at;
}

//! A property to put in a class: name, type, index, offset.
struct Spec { std::string name; uint8_t type; uint16_t index; uint32_t offset; };

/*! A class definition record: superclass, properties, defaults. */
std::vector<uint8_t> classRecord(const std::string& name, const std::string& super, const std::vector<Spec>& props,
                                 const std::vector<uint8_t>& defaults) {
	std::vector<uint8_t> heap;
	const uint32_t nameRef = ascii(heap, name);
	std::vector<std::pair<uint32_t, uint32_t>> refs;
	for (const Spec& p : props) {
		const uint32_t n = ascii(heap, p.name), at = (uint32_t)heap.size();
		heap.push_back(p.type); heap.push_back(0); heap.push_back(0); heap.push_back(0);
		put16(heap, p.index); put32(heap, p.offset); put32(heap, 0);
		put32(heap, 4);                                       // no qualifier
		refs.push_back({ n, at });
	}
	std::vector<uint8_t> b;
	put32(b, (uint32_t)super.size());
	for (char c : super) put16(b, (uint16_t)c);
	for (int i = 0; i < 8; ++i) b.push_back(0);               // timestamp
	put32(b, 0); b.push_back(0); put32(b, nameRef); put32(b, (uint32_t)defaults.size());
	if (super.empty()) put32(b, 4);
	else {
		put32(b, (uint32_t)(4 + 1 + super.size() + 1 + 4));
		b.push_back(0); b.insert(b.end(), super.begin(), super.end()); b.push_back(0); put32(b, (uint32_t)super.size());
	}
	put32(b, 4);                                              // no class qualifier
	put32(b, (uint32_t)refs.size());
	for (const auto& [n, at] : refs) { put32(b, n); put32(b, at); }
	b.insert(b.end(), defaults.begin(), defaults.end());
	put32(b, (uint32_t)heap.size() | 0x80000000);
	b.insert(b.end(), heap.begin(), heap.end());
	return b;
}

/*! __Base (Name, Count = 7 by default) and Derived (+ Command), an instance
 *  of Derived whose Count takes the default, and hostile variants. */
void records() {
	// __Base: Name has no default (state 01), Count's is 7 (state 00); table of 8 bytes.
	std::vector<uint8_t> baseDefaults = { 0x01 };
	for (uint8_t v : { 0, 0, 0, 0, 7, 0, 0, 0 }) baseDefaults.push_back(v);
	const std::vector<uint8_t> base = classRecord("__Base", "", { { "Name", 0x08, 0, 0 }, { "Count", 0x13, 1, 4 } }, baseDefaults);
	// Derived: Name 01, Count 10 (inherited), Command 01; table of 12 bytes.
	std::vector<uint8_t> derivedDefaults = { 0x01 | (0x02 << 2) | (0x01 << 4) };
	derivedDefaults.resize(1 + 12, 0);
	const std::vector<uint8_t> derived = classRecord("Derived", "__Base", { { "Command", 0x08, 2, 8 } }, derivedDefaults);
	CimClass b, d;
	check(parseCimClass(base, b) && b.name == L"__Base" && b.superName.empty() && b.properties.size() == 2
	      && b.properties[1].name == L"Count" && b.properties[1].offset == 4, "class: __Base and its two properties");
	check(parseCimClass(derived, d) && d.name == L"Derived" && d.superName == L"__Base" && d.properties.size() == 1
	      && d.properties[0].index == 2, "class: Derived, its superclass, its own property");

	// The instance: Name set, Count by default, Command in UTF-16.
	std::vector<uint8_t> heap;
	ascii(heap, "Derived");
	const uint32_t alice = ascii(heap, "Alice");
	const uint32_t command = (uint32_t)heap.size();
	heap.push_back(1);
	for (wchar_t c : std::wstring(L"cmd é")) put16(heap, (uint16_t)c);
	put16(heap, 0);
	std::vector<uint8_t> instance(0x80 + 16, 0);
	put32(instance, 0); put32(instance, 0); instance.push_back(0);
	instance.push_back(0x02 << 2);                            // Count: its default
	put32(instance, alice); put32(instance, 0); put32(instance, command);
	put32(instance, 4);                                       // no qualifier
	instance.push_back(1);                                    // no dynamic property
	put32(instance, (uint32_t)heap.size() | 0x80000000);
	instance.insert(instance.end(), heap.begin(), heap.end());
	CimValues values;
	const std::vector<const CimClass*> chain = { &b, &d };
	check(parseCimInstance(instance, chain, values) && values.size() == 3, "instance: three values");
	if (values.size() == 3) {
		check(values[0].first == L"Name" && values[0].second.text() == L"Alice", "instance: a one-byte string");
		check(values[1].first == L"Count" && values[1].second.text() == L"7", "instance: the default inherited from __Base");
		check(values[2].first == L"Command" && values[2].second.text() == L"cmd é", "instance: a UTF-16 string");
	}
	// Not set: left out.
	std::vector<uint8_t> unset = instance;
	unset[0x80 + 16 + 9] |= 0x01 << 4;
	CimValues fewer;
	check(parseCimInstance(unset, chain, fewer) && fewer.size() == 2, "instance: a property not set is left out");
	// Hostile: cut short, a string offset beyond the heap.
	std::vector<uint8_t> cut(instance.begin(), instance.end() - 3);
	CimValues none;
	check(!parseCimInstance(cut, chain, none), "instance: a heap beyond the record accepted");
	// The property count: after the superclass (4 + 6 UTF-16), the header (21), the name again (16), the qualifiers (4).
	std::vector<uint8_t> lying = derived;
	const size_t count = 4 + 12 + 21 + 16 + 4;
	lying[count] = 0xFF; lying[count + 1] = 0xFF;
	CimClass refused;
	check(!parseCimClass(lying, refused), "class: a property count beyond the record accepted");

	// Kinds, by ancestor.
	CimClass consumer, root;
	consumer.name = L"CommandLineEventConsumer";
	root.name = L"__EventConsumer";
	check(wmiSubscriptionKind({ &root, &consumer }) == L"Consumer" && wmiSubscriptionKind({ &b, &d }).empty(),
	      "kind: a consumer by its ancestor, another class none");
}

/*! Mappings: OBJECTS.DATA's then INDEX.BTR's, and a count that lies. */
void mappings() {
	std::vector<uint8_t> file;
	for (int m = 0; m < 2; ++m) {
		put32(file, 0xABCD); put32(file, 7); put32(file, 8); put32(file, 6); put32(file, 3); put32(file, 2);
		for (uint32_t page : { 5u, 0x3FFFFFFFu }) { put32(file, page); put32(file, 0); put32(file, 0); put32(file, 60); put32(file, 0); put32(file, 0); }
		put32(file, 0); put32(file, 0xDCBA);
	}
	CimMapping data, index;
	check(parseCimMappings(file, data, index) && data.physical.size() == 2 && data.physical[0] == 5
	      && data.physical[1] == CimMapping::UNMAPPED && index.indexRoot == 60, "mapping: pages and the index's root");
	file[20] = 0xFF;
	check(!parseCimMappings(file, data, index), "mapping: an entry count beyond the file accepted");
}

/*! The name hash against a real repository: root\subscription's key part,
 *  read in the INDEX.BTR of the test VM. */
void hashes() {
	check(cimNameHash(L"root\\subscription") == "E1DD43413ED9FD9C458D2051F082D1D739399B29035B455F09073926E5ED9870",
	      "hash: root\\subscription as WMI files it");
	check(cimNameHash(L"ROOT\\SUBSCRIPTION") == cimNameHash(L"root\\subscription"), "hash: case does not matter");
}

//! A real repository: its namespaces and subscription objects, printed.
void repository(const std::wstring& folder) {
	CimRepository r;
	const HRESULT opened = r.open(folder + L"\\INDEX.BTR", folder + L"\\OBJECTS.DATA",
	                              { folder + L"\\MAPPING1.MAP", folder + L"\\MAPPING2.MAP", folder + L"\\MAPPING3.MAP" });
	check(opened == ERROR_SUCCESS, "repository: not opened");
	if (opened != ERROR_SUCCESS) return;
	const std::vector<std::wstring> spaces = r.namespaces();
	std::printf("%zu namespace(s)\n", spaces.size());
	for (const std::wstring& space : spaces)
		for (const std::string& hash : r.classHashesWithInstances(space)) {
			const auto chain = r.classChain(space, hash);
			const std::wstring kind = wmiSubscriptionKind(chain);
			if (kind.empty()) continue;
			for (const CimValues& values : r.instances(space, hash, chain)) {
				WmiSubscriptionObject o{ space, kind, chain.back()->name, values };
				std::printf("%s\n", encodeText(o.toJson().dump()).c_str());
			}
		}
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	records();
	mappings();
	hashes();
	if (argc > 1) repository(argv[1]);
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
