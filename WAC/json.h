/*! \file
 *  \brief Centralised JSON serialiser for WAC.
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
    /*! @param v the number.
     *  @return that number, unquoted. */
    static Json num(long long v)           { Json j(Kind::Num);  j.scalar_ = std::to_wstring(v); return j; }
    //! @copydoc num(long long)
    static Json num(unsigned long long v)  { Json j(Kind::Num);  j.scalar_ = std::to_wstring(v); return j; }
    //! @copydoc num(long long)
    static Json num(int v)                 { return num((long long)v); }
    //! @copydoc num(long long)
    static Json num(unsigned int v)        { return num((unsigned long long)v); }
    //! @copydoc num(long long)
    static Json num(unsigned long v)       { return num((unsigned long long)v); }

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

    // --- serialisation ------------------------------------------------------
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

private:
    explicit Json(Kind k) : kind_(k) {}
    static std::wstring tabs(int n) { return std::wstring(n < 0 ? 0 : n, L'\t'); }

    Kind kind_;
    std::wstring scalar_;                                   // Str raw; Num/Bool already formatted
    std::vector<std::pair<std::wstring, Json>> items_;      // Obj: key+value; Arr: empty key
};
