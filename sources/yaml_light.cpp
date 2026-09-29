/*! \file
 *  \brief WAC's configuration file read strictly, through libyaml's events
 *         (see yaml_light.h).
 */
#include "yaml_light.h"
#include <yaml.h>

const YamlNode* YamlNode::child(const std::string& key) const {
	for (const auto& [name, node] : children)
		if (name == key) return node.get();
	return nullptr;
}

namespace {

const size_t MAX_DEPTH = 8;                  //!< a configuration has two or three levels

//! libyaml's parser, released whatever the way out.
struct Parser {
	yaml_parser_t parser;
	bool ready;
	Parser() : ready(yaml_parser_initialize(&parser) != 0) {}
	~Parser() { if (ready) yaml_parser_delete(&parser); }
};

//! libyaml's event, released whatever the way out.
struct Event {
	yaml_event_t event;
	bool held = false;
	~Event() { if (held) yaml_event_delete(&event); }
};

//! "line N: why", N counted from 1.
bool fail(std::string& error, size_t line, const std::string& why) {
	error = "line " + std::to_string(line + 1) + ": " + why;
	return false;
}

/*! Whether an event carries what a configuration does not use: an anchor
 *  or a tag (an alias is refused by its own event). */
bool decorated(const yaml_event_t& e) {
	if (e.type == YAML_SCALAR_EVENT) return e.data.scalar.anchor || (e.data.scalar.tag && !e.data.scalar.plain_implicit && !e.data.scalar.quoted_implicit);
	if (e.type == YAML_MAPPING_START_EVENT) return e.data.mapping_start.anchor || e.data.mapping_start.tag;
	return false;
}

} // namespace

bool YamlParse(const std::string& text, YamlNode& root, std::string& error) {
	root = YamlNode{};
	root.mapping = true;
	Parser p;
	if (!p.ready) { error = "YAML reader not initialised"; return false; }
	yaml_parser_set_input_string(&p.parser, reinterpret_cast<const unsigned char*>(text.data()), text.size());
	yaml_parser_set_encoding(&p.parser, YAML_UTF8_ENCODING);

	std::vector<YamlNode*> open;                 // the mappings being filled, innermost last
	std::string key;                             // a key read, waiting for its value
	size_t keyLine = 0;                          // its line: the one a message about the setting names
	bool haveKey = false;
	size_t documents = 0;
	for (;;) {
		Event e;
		if (!yaml_parser_parse(&p.parser, &e.event)) {
			// The line where the faulty construct began (libyaml's context) tells more than where it ended.
			const std::string problem = p.parser.problem ? p.parser.problem : "unreadable YAML";
			if (p.parser.context)
				return fail(error, p.parser.context_mark.line, std::string(p.parser.context) + ": " + problem);
			return fail(error, p.parser.problem_mark.line, problem);
		}
		e.held = true;
		const size_t line = e.event.start_mark.line;
		if (decorated(e.event)) return fail(error, line, "anchors and tags are not accepted");
		switch (e.event.type) {
		case YAML_STREAM_START_EVENT:
		case YAML_DOCUMENT_END_EVENT:
			break;
		case YAML_DOCUMENT_START_EVENT:
			if (++documents > 1) return fail(error, line, "one document only");
			break;
		case YAML_STREAM_END_EVENT:
			return true;
		case YAML_SEQUENCE_START_EVENT:
			return fail(error, line, "lists are not accepted");
		case YAML_ALIAS_EVENT:
			return fail(error, line, "aliases are not accepted");
		case YAML_MAPPING_START_EVENT: {
			if (open.empty()) {                      // the document's top mapping
				if (root.line) return fail(error, line, "one top-level mapping only");
				root.line = (int)line + 1;
				open.push_back(&root);
				break;
			}
			if (!haveKey) return fail(error, line, "a mapping cannot be a key");
			if (open.size() >= MAX_DEPTH) return fail(error, line, "nested too deep");
			auto node = std::make_unique<YamlNode>();
			node->mapping = true;
			node->line = (int)keyLine + 1;
			YamlNode* inner = node.get();
			open.back()->children.emplace_back(key, std::move(node));
			open.push_back(inner);
			haveKey = false;
			break;
		}
		case YAML_MAPPING_END_EVENT:
			open.pop_back();
			break;
		case YAML_SCALAR_EVENT: {
			const std::string value(reinterpret_cast<const char*>(e.event.data.scalar.value), e.event.data.scalar.length);
			if (open.empty()) {
				// A document holding a single scalar — or nothing but comments.
				if (!value.empty()) return fail(error, line, "the file must be a mapping of settings");
				break;
			}
			if (!haveKey) {
				if (open.back()->child(value)) return fail(error, line, "key \"" + value + "\" given twice");
				key = value;
				keyLine = line;
				haveKey = true;
				break;
			}
			auto node = std::make_unique<YamlNode>();
			node->scalar = value;
			node->line = (int)keyLine + 1;
			open.back()->children.emplace_back(key, std::move(node));
			haveKey = false;
			break;
		}
		default:
			return fail(error, line, "unexpected YAML construct");
		}
	}
}
