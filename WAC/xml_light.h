/*! \file
 *  \brief Minimal XML reader, with no dependency.
 *
 *  WHY NOT MSXML. Reading the scheduled task definitions offline is only worth
 *  it if the COM execution trace is removed; going through MSXML, which is a COM
 *  component, would cancel precisely that benefit. Hence this self-contained
 *  reader.
 *
 *  AN ASSUMED SCOPE. This is NOT a conforming XML parser: it handles neither
 *  dynamically declared namespaces, nor DTDs, nor entities other than the five
 *  predefined ones, nor nested CDATA sections. It handles the subset actually
 *  produced by the Windows task scheduler, whose schema is narrow and stable
 *  (`<RegistrationInfo>`, `<Triggers>`, `<Actions>`, `<Principals>`,
 *  `<Settings>`).
 *
 *  The files parsed coming from a suspect machine, the parsing is defensive: no
 *  unbounded recursion, no access out of the buffer, and any malformed document
 *  returns an empty tree rather than throwing an exception.
 */
#pragma once
#include <string>
#include <vector>
#include <memory>

/*! An XML element: name, attributes, text, children. */
struct XmlNode {
	std::wstring name;                                  //!< local name, without the namespace prefix
	std::wstring text;                                //!< direct text content, edge spaces stripped
	std::vector<std::pair<std::wstring, std::wstring>> attributes;
	std::vector<std::unique_ptr<XmlNode>> children;

	/*! First child carrying that name, or nullptr. */
	const XmlNode* child(const std::wstring& childName) const;

	/*! Text of the first child carrying that name, or an empty string.
	 *  @param path a simple name, or a path separated by '/' (e.g. L"Actions/Exec/Command") */
	std::wstring textOf(const std::wstring& path) const;

	/*! Value of an attribute, or an empty string. */
	std::wstring attribute(const std::wstring& attributeName) const;

	/*! Every descendant carrying that name, at any depth.
	 *  Useful to collect the triggers or the actions without knowing their exact
	 *  level of nesting. */
	std::vector<const XmlNode*> descendants(const std::wstring& wantedName) const;
};

/*! Parses an XML document in memory.
 *  @param content the complete document (UTF-16; the caller handles the decoding)
 *  @return the root, or nullptr if the document is malformed or empty
 */
std::unique_ptr<XmlNode> xmlParse(const std::wstring& content);

/*! Reads an XML file encoded in UTF-8 or UTF-16 and parses it.
 *  The encoding is deduced from the byte-order mark, UTF-8 by default: the
 *  scheduler writes its tasks in UTF-16LE with a BOM.
 *  @return the root, or nullptr if the file is unreadable or malformed
 */
std::unique_ptr<XmlNode> xmlReadFile(const std::wstring& path);
