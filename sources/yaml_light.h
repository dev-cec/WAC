/*! \file
 *  \brief WAC'S CONFIGURATION FILE (wac.yml), read strictly.
 *
 *  WHY STRICT. The configuration decides what a collection takes: a value
 *  misread — a duplicate key silently overriding the first, a list where a
 *  value was expected — would change the procedure without anyone knowing.
 *  The YAML itself is read by libyaml, the reference implementation
 *  (third_party/libyaml-0.2.5, see its VENDORED.md); WAC takes its events and
 *  keeps only what a configuration needs, refusing the rest with the line at
 *  fault:
 *    - mappings of scalars, nested, and lists of scalars as a key's value
 *      (the folders a deleted-file recovery leaves out) — nothing else;
 *    - a duplicate key, a list of anything but scalars, a list not under a
 *      key, an anchor, an alias, a tag, a second document: refused;
 *    - nesting beyond a few levels: refused.
 *  What the keys mean, and which values they take, is config.cpp's: this
 *  module only reads the tree.
 *
 *  Portable C++: see yaml_light_test.
 */
#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

/*! A node: a mapping (children, in the file's order), a list of scalars, or a scalar. */
struct YamlNode {
	bool mapping = false;
	bool list = false;             //!< a list of scalars: `items`
	std::string scalar;            //!< the value, quotes removed, when neither a mapping nor a list
	std::vector<std::string> items;   //!< the list's values, in the file's order
	int line = 0;                  //!< line of the key, for messages
	std::vector<std::pair<std::string, std::unique_ptr<YamlNode>>> children;

	//! @return the child of that key, or nullptr
	const YamlNode* child(const std::string& key) const;
};

/*! Parses a configuration text.
 *  @param text the file's content, UTF-8 (a leading byte order mark is skipped)
 *  @param root receives the top-level mapping
 *  @param error receives "line N: why" when refused
 *  @return false if the text is not within the subset */
bool YamlParse(const std::string& text, YamlNode& root, std::string& error);
