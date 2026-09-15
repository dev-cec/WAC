/*  json.h — sérialiseur JSON centralisé pour WAC.
 *
 *  POURQUOI. Chaque artefact fabriquait son JSON à la main par concaténation de
 *  chaînes. Conséquences constatées en test : échappement oublié ou incohérent
 *  (ScheduledTasks, mounted_device), virgule finale invalide (Sessions), nombres
 *  émis comme chaînes, indentation gérée à la main. Ce writer rend ces erreurs
 *  structurellement impossibles.
 *
 *  PRINCIPE. Les valeurs sont stockées BRUTES en mémoire (vrais chemins,
 *  utilisables tels quels pour les I/O fichier) ; l'échappement n'a lieu QU'ICI,
 *  à la sérialisation, et une seule fois.
 *
 *  Autonome (aucune dépendance au reste de WAC) : testable sous Linux.
 *
 *  Exemple :
 *      Json o = Json::obj();
 *      o.add(L"SessionId", Json::num(sessionId));       // nombre, sans guillemets
 *      o.add(L"LogonName", Json::str(logonName));       // échappé automatiquement
 *      o.add(L"Path",      Json::str(cheminBrut));      // chemin brut, échappé ici
 *      return o.dump(1);
 */
#pragma once
#include <string>
#include <vector>
#include <utility>

/*! Échappe une chaîne pour une valeur JSON (\\ , " , contrôles < 0x20). */
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
            if (c < 0x20) {                       // autres caractères de contrôle
                static const wchar_t* h = L"0123456789abcdef";
                r += L"\\u00"; r += h[(c >> 4) & 0xF]; r += h[c & 0xF];
            }
            else r += c;
        }
    }
    return r;
}

/*! Valeur JSON : objet, tableau ou scalaire. L'ordre d'insertion est conservé. */
class Json {
public:
    enum class Kind { Obj, Arr, Str, Num, Bool, Null };

    // --- fabriques ---------------------------------------------------------
    static Json obj()  { return Json(Kind::Obj); }
    static Json arr()  { return Json(Kind::Arr); }
    static Json null() { return Json(Kind::Null); }
    static Json str(const std::wstring& v) { Json j(Kind::Str);  j.scalar_ = v; return j; }
    static Json boolean(bool v)            { Json j(Kind::Bool); j.scalar_ = v ? L"true" : L"false"; return j; }
    static Json num(long long v)           { Json j(Kind::Num);  j.scalar_ = std::to_wstring(v); return j; }
    static Json num(unsigned long long v)  { Json j(Kind::Num);  j.scalar_ = std::to_wstring(v); return j; }
    static Json num(int v)                 { return num((long long)v); }
    static Json num(unsigned int v)        { return num((unsigned long long)v); }
    static Json num(unsigned long v)       { return num((unsigned long long)v); }

    // --- construction ------------------------------------------------------
    /*! Ajoute une paire clé/valeur (objet). */
    Json& add(const std::wstring& cle, Json valeur) {
        items_.emplace_back(cle, std::move(valeur));
        return *this;
    }
    /*! Fusionne les membres d'un autre objet dans celui-ci (mise à plat).
     *  Utile quand un sous-objet doit apparaître au même niveau que le parent. */
    Json& merge(Json autre) {
        for (auto& kv : autre.items_) items_.push_back(std::move(kv));
        return *this;
    }
    /*! Ajoute un élément (tableau). */
    Json& push(Json valeur) {
        items_.emplace_back(std::wstring(), std::move(valeur));
        return *this;
    }
    bool empty() const { return items_.empty(); }
    size_t size() const { return items_.size(); }
    /*! Nature de la valeur, pour adapter un traitement (ex. envelopper un
     *  scalaire dans un tableau quand le schema de sortie exige un tableau). */
    Kind kind() const { return kind_; }

    // --- sérialisation -----------------------------------------------------
    /*! Sérialise. @param niveau profondeur d'indentation (tabulations). */
    std::wstring dump(int niveau = 0) const {
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
        const std::wstring ind  = tabs(niveau);
        const std::wstring ind1 = tabs(niveau + 1);
        std::wstring r = o ? L"{\n" : L"[\n";
        for (size_t i = 0; i < items_.size(); ++i) {
            r += ind1;
            if (o) r += L"\"" + jsonEscape(items_[i].first) + L"\": ";
            r += items_[i].second.dump(niveau + 1);
            if (i + 1 < items_.size()) r += L",";     // jamais de virgule finale
            r += L"\n";
        }
        r += ind + (o ? L"}" : L"]");
        return r;
    }

private:
    explicit Json(Kind k) : kind_(k) {}
    static std::wstring tabs(int n) { return std::wstring(n < 0 ? 0 : n, L'\t'); }

    Kind kind_;
    std::wstring scalar_;                                   // Str brute ; Num/Bool déjà formatés
    std::vector<std::pair<std::wstring, Json>> items_;      // Obj: clé+valeur ; Arr: clé vide
};
