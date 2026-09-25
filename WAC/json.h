/*! \file
 *  \brief Centralised JSON serialiser for WAC, and the reader of the JSON it
 *         writes back (exhibit manifest, snapshot of the live state).
 *
 *  WHY. Every artefact used to build its JSON by hand, concatenating strings.
 *  What that produced, as found in testing: forgotten or inconsistent escaping
 *  (ScheduledTasks, mounted_device), an invalid trailing comma (Sessions),
 *  numbers emitted as strings, indentation kept by hand. This writer makes
 *  those mistakes structurally impossible.
 *
 *  PRINCIPLE. Values are stored RAW in memory (real paths, usable as they are
 *  for file I/O); escaping happens ONLY HERE, at serialisation time, and only
 *  once.
 *
 *  Self-contained (no dependency on the rest of WAC): testable under Linux.
 *
 *  Example:
 *      Json o = Json::obj();
 *      o.add(L"SessionId", Json::num(sessionId));       // a number, unquoted
 *      o.add(L"LogonName", Json::str(logonName));       // escaped automatically
 *      o.add(L"Path",      Json::str(rawPath));      // raw path, escaped here
 *      return o.dump(1);
 */
#pragma once
#include <type_traits>
#include <string>
#include <vector>
#include <utility>

/*! Escapes a string for use as a JSON value (\\ , " , controls < 0x20).
 *  @param s the raw string.
 *  @return the escaped string, without the surrounding quotes. */
inline std::wstring jsonEscape(const std::wstring& s) {
    std::wstring r;
    r.reserve(s.size() + 8);
    for (wchar_t c : s) {
        switch (c) {
        case L'\\': r += L"\\\\"; break;
        case L'"':  r += L"\\\""; break;
        case L'\b': r += L"\\b";  break;
        case L'\f': r += L"\\f";  break;
        case L'\n': r += L"\\n";  break;
        case L'\r': r += L"\\r";  break;
        case L'\t': r += L"\\t";  break;
        default:
            if (c < 0x20) {                       // other control characters
                static const wchar_t* h = L"0123456789abcdef";
                r += L"\\u00"; r += h[(c >> 4) & 0xF]; r += h[c & 0xF];
            }
            else r += c;
        }
    }
    return r;
}

/*! A JSON value: object, array or scalar. Insertion order is preserved.
 *
 *  A value is built through the factories (`obj`, `arr`, `str`, `num`…), filled
 *  through `add` (objects) or `push` (arrays), then serialised by `dump`. */
class Json {
public:
    /*! The nature of a value, which decides how it is serialised. */
    enum class Kind {
        Obj,    //!< object: `{ "key": value, … }`
        Arr,    //!< array: `[ value, … ]`
        Str,    //!< string, escaped at serialisation time
        Num,    //!< number, emitted unquoted
        Bool,   //!< `true` or `false`
        Null    //!< `null`, which `add` never emits
    };

    // --- factories ---------------------------------------------------------
    //! @return an empty object.
    static Json obj()  { return Json(Kind::Obj); }
    //! @return an empty array.
    static Json arr()  { return Json(Kind::Arr); }
    //! @return the `null` value.
    static Json null() { return Json(Kind::Null); }
    /*! @param v the raw string, escaped only at serialisation time.
     *  @return that string as a JSON value. */
    static Json str(const std::wstring& v) { Json j(Kind::Str);  j.scalar_ = v; return j; }
    /*! @param v the value.
     *  @return `true` or `false`, unquoted. */
    static Json boolean(bool v)            { Json j(Kind::Bool); j.scalar_ = v ? L"true" : L"false"; return j; }
    /*! One template for every integer type, instead of one overload per type
     *  (there were five). A bool is refused: it is Json::boolean.
     *  @param v the number.
     *  @return that number, unquoted. */
    template <typename T,
              typename = std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>>>
    static Json num(T v)                   { Json j(Kind::Num);  j.scalar_ = std::to_wstring(v); return j; }

    // --- construction ------------------------------------------------------
    /*! Adds a key/value pair to an object — UNLESS the value is empty.
     *
     *  THE ONE RULE: a field without a value is not emitted. An empty key reads
     *  as a failed read, and cannot be told apart from "the source does not hold
     *  that value". The rule used to be applied collector by collector, hence
     *  unevenly: a real collection still counted 129,837 `null` in events.json,
     *  and empty strings or arrays in scheduled tasks, Amcache, Shimcache,
     *  shortcuts, shellbags… It now lives here, where every field goes through,
     *  so that the next collector cannot forget it.
     *
     *  Empty means: `null`, an empty string, an object or array with no element.
     *  A zero number and a false boolean are values, and are emitted. Array
     *  elements (`push`) are not concerned: a file with no entry stays "[]",
     *  which means "no entry found".
     *
     *  @param key the key.
     *  @param value the value, moved into the object.
     *  @return this object, so calls can be chained. */
    Json& add(const std::wstring& key, Json value) {
        if (value.isEmptyValue()) return *this;
        items_.emplace_back(key, std::move(value));
        return *this;
    }
    /*! @return true for `null`, an empty string, or an object or array with no
     *  element — the values `add` does not emit. */
    bool isEmptyValue() const {
        switch (kind_) {
        case Kind::Null: return true;
        case Kind::Str:  return scalar_.empty();
        case Kind::Obj:
        case Kind::Arr:  return items_.empty();
        default:         return false;
        }
    }
    /*! Merges another object's members into this one (flattening).
     *  Useful when a sub-object must appear at the same level as its parent.
     *  @param other the object whose members are taken over.
     *  @return this object, so calls can be chained. */
    Json& merge(Json other) {
        for (auto& kv : other.items_) items_.push_back(std::move(kv));
        return *this;
    }
    /*! Adds an element to an array. Unlike `add`, an empty element is kept.
     *  @param value the element, moved into the array.
     *  @return this array, so calls can be chained. */
    Json& push(Json value) {
        items_.emplace_back(std::wstring(), std::move(value));
        return *this;
    }
    //! @return true if the object or array holds no member.
    bool empty() const { return items_.empty(); }
    //! @return the number of members of the object or array.
    size_t size() const { return items_.size(); }
    /*! @return the nature of the value, to adapt a treatment to it (for
     *  instance wrapping a scalar in an array when the output schema requires
     *  an array). */
    Kind kind() const { return kind_; }

    // --- serialization ------------------------------------------------------
    /*! Serialises the value.
     *  @param level indentation depth, in tabulations.
     *  @return the JSON text, without a trailing newline. */
    std::wstring dump(int level = 0) const {
        switch (kind_) {
        case Kind::Null: return L"null";
        case Kind::Num:
        case Kind::Bool: return scalar_;
        case Kind::Str:  return L"\"" + jsonEscape(scalar_) + L"\"";
        case Kind::Obj:
        case Kind::Arr:  break;
        }
        const bool o = (kind_ == Kind::Obj);
        if (items_.empty()) return o ? L"{}" : L"[]";
        const std::wstring ind  = tabs(level);
        const std::wstring ind1 = tabs(level + 1);
        std::wstring r = o ? L"{\n" : L"[\n";
        for (size_t i = 0; i < items_.size(); ++i) {
            r += ind1;
            if (o) r += L"\"" + jsonEscape(items_[i].first) + L"\": ";
            r += items_[i].second.dump(level + 1);
            if (i + 1 < items_.size()) r += L",";     // never a trailing comma
            r += L"\n";
        }
        r += ind + (o ? L"}" : L"]");
        return r;
    }

    // --- reading -----------------------------------------------------------
    /*! The text of a scalar: the raw string of a Str, the digits of a Num,
     *  "true"/"false" of a Bool; empty for the other kinds. */
    const std::wstring& text() const { return scalar_; }
    /*! A member of an object.
     *  @param key the key
     *  @return the value, or nullptr if the object has no such key (or this is
     *          not an object) */
    const Json* find(const std::wstring& key) const {
        if (kind_ != Kind::Obj) return nullptr;
        for (const auto& kv : items_) if (kv.first == key) return &kv.second;
        return nullptr;
    }
    /*! The members of an object (key, value) or the elements of an array (empty
     *  key, value), in order. */
    const std::vector<std::pair<std::wstring, Json>>& members() const { return items_; }

    /*! Reads a JSON text — the exhibit manifest, the snapshot of the live
     *  state — back into a value.
     *
     *  HOSTILE INPUT. The file comes from a collection medium: strict grammar
     *  (RFC 8259), every read bounded by the text's length, nesting limited
     *  (MAX_DEPTH), and nothing accepted after the value. A malformed text is
     *  refused whole, never half read.
     *  @param text the JSON text
     *  @param out receives the value
     *  @param error receives the reason of a refusal, with its position
     *  @return true if the whole text is one valid JSON value */
    static bool parse(const std::wstring& text, Json& out, std::wstring& error) {
        Reader r{ text, 0, 0, L"" };
        out = Json(Kind::Null);
        if (!r.value(out)) { error = r.error; return false; }
        r.blank();
        if (r.pos != text.size()) { error = L"unexpected text after the value at " + std::to_wstring(r.pos); return false; }
        return true;
    }

private:
    explicit Json(Kind k) : kind_(k) {}

    //! Depth beyond which a text is refused: WAC writes a few levels only.
    static constexpr int MAX_DEPTH = 64;

    //! The recursive-descent reader behind parse().
    struct Reader {
        const std::wstring& s;
        size_t pos;
        int depth;
        std::wstring error;

        bool fail(const wchar_t* why) { error = std::wstring(why) + L" at " + std::to_wstring(pos); return false; }
        void blank() { while (pos < s.size() && (s[pos] == L' ' || s[pos] == L'\t' || s[pos] == L'\n' || s[pos] == L'\r')) ++pos; }
        bool literal(const wchar_t* word) {
            for (size_t k = 0; word[k]; ++k, ++pos)
                if (pos >= s.size() || s[pos] != word[k]) return fail(L"invalid literal");
            return true;
        }
        bool hex4(unsigned& v) {
            if (s.size() - pos < 4) return fail(L"truncated \\u escape");
            v = 0;
            for (int k = 0; k < 4; ++k, ++pos) {
                const wchar_t c = s[pos];
                v <<= 4;
                if (c >= L'0' && c <= L'9') v |= (unsigned)(c - L'0');
                else if (c >= L'a' && c <= L'f') v |= (unsigned)(c - L'a' + 10);
                else if (c >= L'A' && c <= L'F') v |= (unsigned)(c - L'A' + 10);
                else return fail(L"invalid \\u escape");
            }
            return true;
        }
        bool string(std::wstring& out) {
            ++pos;   // the opening quote
            out.clear();
            while (true) {
                if (pos >= s.size()) return fail(L"unterminated string");
                const wchar_t c = s[pos++];
                if (c == L'"') return true;
                if (c < 0x20) return fail(L"control character in a string");
                if (c != L'\\') { out += c; continue; }
                if (pos >= s.size()) return fail(L"truncated escape");
                const wchar_t e = s[pos++];
                switch (e) {
                case L'"': out += L'"'; break;
                case L'\\': out += L'\\'; break;
                case L'/': out += L'/'; break;
                case L'b': out += L'\b'; break;
                case L'f': out += L'\f'; break;
                case L'n': out += L'\n'; break;
                case L'r': out += L'\r'; break;
                case L't': out += L'\t'; break;
                case L'u': { unsigned v = 0; if (!hex4(v)) return false; out += (wchar_t)v; break; }
                default: return fail(L"invalid escape");
                }
            }
        }
        bool number(Json& out) {
            const size_t start = pos;
            if (pos < s.size() && s[pos] == L'-') ++pos;
            if (pos >= s.size()) return fail(L"truncated number");
            if (s[pos] == L'0') ++pos;
            else if (s[pos] >= L'1' && s[pos] <= L'9') { while (pos < s.size() && s[pos] >= L'0' && s[pos] <= L'9') ++pos; }
            else return fail(L"invalid number");
            if (pos < s.size() && s[pos] == L'.') {
                ++pos;
                if (pos >= s.size() || s[pos] < L'0' || s[pos] > L'9') return fail(L"invalid fraction");
                while (pos < s.size() && s[pos] >= L'0' && s[pos] <= L'9') ++pos;
            }
            if (pos < s.size() && (s[pos] == L'e' || s[pos] == L'E')) {
                ++pos;
                if (pos < s.size() && (s[pos] == L'+' || s[pos] == L'-')) ++pos;
                if (pos >= s.size() || s[pos] < L'0' || s[pos] > L'9') return fail(L"invalid exponent");
                while (pos < s.size() && s[pos] >= L'0' && s[pos] <= L'9') ++pos;
            }
            out = Json(Kind::Num);
            out.scalar_ = s.substr(start, pos - start);
            return true;
        }
        bool value(Json& out) {
            blank();
            if (pos >= s.size()) return fail(L"missing value");
            const wchar_t c = s[pos];
            if (c == L'{' || c == L'[') {
                if (++depth > MAX_DEPTH) return fail(L"nesting too deep");
                const bool object = (c == L'{');
                out = Json(object ? Kind::Obj : Kind::Arr);
                ++pos;
                blank();
                if (pos < s.size() && s[pos] == (object ? L'}' : L']')) { ++pos; --depth; return true; }
                while (true) {
                    std::wstring key;
                    if (object) {
                        blank();
                        if (pos >= s.size() || s[pos] != L'"') return fail(L"expected a key");
                        if (!string(key)) return false;
                        blank();
                        if (pos >= s.size() || s[pos] != L':') return fail(L"expected ':'");
                        ++pos;
                    }
                    Json member(Kind::Null);
                    if (!value(member)) return false;
                    out.items_.emplace_back(std::move(key), std::move(member));
                    blank();
                    if (pos >= s.size()) return fail(object ? L"unterminated object" : L"unterminated array");
                    if (s[pos] == L',') { ++pos; continue; }
                    if (s[pos] == (object ? L'}' : L']')) { ++pos; --depth; return true; }
                    return fail(L"expected ',' or a closing bracket");
                }
            }
            if (c == L'"') { out = Json(Kind::Str); return string(out.scalar_); }
            if (c == L't') { if (!literal(L"true")) return false;  out = Json(Kind::Bool); out.scalar_ = L"true";  return true; }
            if (c == L'f') { if (!literal(L"false")) return false; out = Json(Kind::Bool); out.scalar_ = L"false"; return true; }
            if (c == L'n') { if (!literal(L"null")) return false;  out = Json(Kind::Null); return true; }
            if (c == L'-' || (c >= L'0' && c <= L'9')) return number(out);
            return fail(L"unexpected character");
        }
    };
    static std::wstring tabs(int n) { return std::wstring(n < 0 ? 0 : n, L'\t'); }

    Kind kind_;
    std::wstring scalar_;                                   // Str raw; Num/Bool already formatted
    std::vector<std::pair<std::wstring, Json>> items_;      // Obj: key+value; Arr: empty key
};
