/*! \file
 *  \brief WMI event subscriptions (see wmi_persistence.h).
 */
#include "wmi_persistence.h"
#include "consigne.h"

namespace {

//! The repository's folder, relative to the system volume, in lower case as the manifest index is.
const wchar_t REPOSITORY_FOLDER[] = L"\\windows\\system32\\wbem\\repository\\";

//! The exhibit of a repository file; empty if not collected.
std::wstring repositoryFile(const std::wstring& name) {
	const auto& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(conf.systemDrive.substr(0, 2)) + REPOSITORY_FOLDER + name);
	return found == index.end() ? std::wstring() : found->second.workingFile;
}

//! A binary SID (an array of bytes, as CreatorSID is kept) in its text form.
Json sidValue(const Json& bytes) {
	if (bytes.kind() != Json::Kind::Arr) return bytes;
	std::vector<BYTE> sid;
	for (const auto& member : bytes.members()) sid.push_back((BYTE)_wtoi(member.second.text().c_str()));
	const std::wstring text = sidToText(sid.data(), sid.size());
	return text.empty() ? bytes : Json::str(text);
}

} // namespace

std::wstring wmiSubscriptionKind(const std::vector<const CimClass*>& chain) {
	static const std::pair<const wchar_t*, const wchar_t*> KINDS[] = {
		{ L"__EventFilter", L"Filter" }, { L"__EventConsumer", L"Consumer" },
		{ L"__FilterToConsumerBinding", L"Binding" }, { L"__TimerInstruction", L"Timer" },
	};
	for (const CimClass* c : chain)
		for (const auto& [base, kind] : KINDS)
			if (_wcsicmp(c->name.c_str(), base) == 0) return kind;
	return L"";
}

Json WmiSubscriptionObject::toJson() const {
	Json o = Json::obj();
	o.add(L"Namespace", Json::str(space));
	o.add(L"Kind", Json::str(kind));
	o.add(L"Class", Json::str(className));
	// Name/Value pairs: a class an intruder defined may name its properties anyhow.
	Json list = Json::arr();
	for (const auto& [name, value] : values) {
		Json item = Json::obj();
		item.add(L"Name", Json::str(name));
		item.add(L"Value", name == L"CreatorSID" ? sidValue(value) : Json(value));
		list.push(std::move(item));
	}
	o.add(L"Properties", std::move(list));
	return o;
}

HRESULT WmiPersistence::getData() {
	log(0, L"ℹ️WMI subscriptions :");
	std::vector<std::wstring> mappings;
	for (const wchar_t* name : { L"mapping1.map", L"mapping2.map", L"mapping3.map" }) {
		const std::wstring file = repositoryFile(name);
		if (!file.empty()) mappings.push_back(file);
	}
	const std::wstring index = repositoryFile(L"index.btr"), objects = repositoryFile(L"objects.data");
	if (index.empty() || objects.empty() || mappings.empty()) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	CimRepository repository;
	const HRESULT opened = repository.open(index, objects, mappings);
	if (opened != ERROR_SUCCESS) return opened;
	const std::vector<std::wstring> spaces = repository.namespaces();
	namespaces_ = spaces.size();
	for (const std::wstring& space : spaces) {
		// Only the classes with instances here: CI_ and CD_ share the class's hash.
		for (const std::string& hash : repository.classHashesWithInstances(space)) {
			const std::vector<const CimClass*> chain = repository.classChain(space, hash);
			const std::wstring kind = wmiSubscriptionKind(chain);
			if (kind.empty()) continue;
			for (CimValues& values : repository.instances(space, hash, chain))
				objects_.push_back({ space, kind, chain.back()->name, std::move(values) });
		}
	}
	log(2, L"❇️" + std::to_wstring(namespaces_) + L" namespace(s), " + std::to_wstring(objects_.size()) + L" subscription object(s)");
	return ERROR_SUCCESS;
}

HRESULT WmiPersistence::toJson() {
	Json list = Json::arr();
	for (const WmiSubscriptionObject& o : objects_) list.push(o.toJson());
	return writeJsonFile("wmi_persistence.json", list);
}

void WmiPersistence::clear() {
	objects_.clear();
}
