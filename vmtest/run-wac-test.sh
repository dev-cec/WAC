#!/usr/bin/env bash
# run-wac-test.sh — cycle de test WAC entièrement autonome dans la VM Windows.
#
# Enchaîne, sans aucune interaction : build (option) -> envoi des binaires dans la
# VM -> exécution de WAC en SYSTEM (droits admin, pas d'UAC) -> rapatriement du
# log et des JSON sur l'hôte pour inspection.
#
# Prérequis : qemu-guest-agent installé et répondant dans la VM (`qga.py ping`).
# Usage : ./run-wac-test.sh [--build] [--raw-only]
set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RACINE="$(cd "$ICI/.." && pwd)"
QGA="python3 $ICI/qga.py"
VMDIR='C:\wactest'
HORO="$(date +%Y%m%d-%H%M%S)"
SORTIE="$ICI/results/$HORO"
mkdir -p "$SORTIE"

BUILD=0; RAWONLY=0
for a in "$@"; do
  [[ "$a" == "--build"    ]] && BUILD=1
  [[ "$a" == "--raw-only" ]] && RAWONLY=1
done

echo "== 0. Agent =="
$QGA ping

if [[ $BUILD -eq 1 ]]; then
  echo "== 1. Build (cross-compilation Linux) =="
  "$RACINE/build-windows.sh" --test >/dev/null
  echo "   WAC.exe + raw_hive_test.exe reconstruits"
fi

echo "== 2. Envoi des binaires dans la VM =="
$QGA run --shell "if not exist $VMDIR mkdir $VMDIR" >/dev/null

# Un run précédent interrompu (Ctrl+C sur l'hôte, collecte bloquée, plantage)
# laisse WAC.exe en cours dans la VM. Windows verrouille alors le fichier et
# l'envoi échoue — chaque test suivant échoue jusqu'à un nettoyage manuel.
# On termine donc les binaires résiduels avant d'écrire, sans faire de bruit
# quand il n'y en a pas.
for exe in WAC.exe raw_hive_test.exe; do
  $QGA run --shell "taskkill /f /im $exe >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true
done
# reg load laissé monté par un run interrompu : il verrouille la ruche extraite.
$QGA run --shell "reg unload HKLM\\WAC_TEST >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true

$QGA write "$RACINE/build-windows/WAC.exe"           "$VMDIR\\WAC.exe"
$QGA write "$RACINE/build-windows/raw_hive_test.exe" "$VMDIR\\raw_hive_test.exe"

echo "== 3. Validation raw_hive (extraction brute + reg load) =="
# Testé dans les DEUX sens. Une ruche copiée à chaud est toujours « dirty » :
#   - sans --fix, `reg load` DOIT la refuser (ERROR_BADDB) : c'est ce qui prouve
#     que hive_recover est nécessaire, et non un luxe ;
#   - avec --fix, elle DOIT charger.
# Un test qui échoue par construction (ce qui était le cas ici) finit par être
# ignoré, ce qui est pire que pas de test du tout.
# `echo OK & ...` en cmd laisse l'espace qui précède le `&` dans la sortie :
# sans nettoyage, toute comparaison exacte devient un faux négatif.
nettoie() { tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

{
  $QGA run --shell "cd /d $VMDIR && raw_hive_test.exe C \\Windows\\System32\\config\\SYSTEM $VMDIR\\SYSTEM_dirty.hiv > raw-dirty.log 2>&1" || true
  SANS=$($QGA run --shell "reg load HKLM\\WAC_TEST $VMDIR\\SYSTEM_dirty.hiv >nul 2>&1 && (echo CHARGE & reg unload HKLM\\WAC_TEST >nul) || echo REFUSEE" 2>/dev/null | nettoie || true)
  if [[ "$SANS" == "REFUSEE" ]]; then
    echo "REG_LOAD_SANS_PATCH=REFUSEE (attendu : la ruche brute est dirty)"
  else
    echo "REG_LOAD_SANS_PATCH=$SANS (INATTENDU : la ruche brute était déjà propre)"
  fi

  $QGA run --shell "cd /d $VMDIR && raw_hive_test.exe C \\Windows\\System32\\config\\SYSTEM $VMDIR\\SYSTEM.hiv --fix > raw.log 2>&1" || true
  AVEC=$($QGA run --shell "reg load HKLM\\WAC_TEST $VMDIR\\SYSTEM.hiv >nul 2>&1 && (echo OK & reg unload HKLM\\WAC_TEST >nul) || echo ECHEC" 2>/dev/null | nettoie || true)
  echo "REG_LOAD_AVEC_PATCH=$AVEC"
  [[ "$AVEC" == "OK" ]] || echo "   ❌ la ruche patchée reste illisible : régression de raw_hive ou hive_recover"

  # Énumération de répertoire : la brique de ExtractDirectoryRaw.
  # Le filtrage se fait sur l'hôte : un `findstr` côté invité, dans un pipe passé
  # à cmd /c, ne remontait rien alors que la commande seule fonctionne.
  NB=$($QGA run --shell "cd /d $VMDIR && raw_hive_test.exe C \\Windows\\Prefetch x --list 2>&1" 2>/dev/null \
       | grep -a '^Total:' | nettoie || true)
  echo "LIST_PREFETCH=${NB:-(aucune sortie)}"
} | tee "$SORTIE/raw-validation.txt"
$QGA read "$VMDIR\\raw.log" "$SORTIE/raw.log" >/dev/null 2>&1 || true

if [[ $RAWONLY -eq 1 ]]; then
  echo "== Terminé (raw seulement). Résultats : $SORTIE =="
  exit 0
fi

echo "== 4. Exécution de WAC (SYSTEM) =="
# --output doit être un nom simple (WAC refuse les backslash) : créé sous cwd.
# Une collecte qui s'arrête en cours de route produit quand même des JSON
# valides : l'absence d'erreur JSON ne prouve donc PAS que WAC est allé au bout.
# qga.py rend le code de sortie de la commande invitée, on le contrôle.
CODE=0
# Le journal de WAC est ouvert en APPEND : sans purge il grossit d'un test a
# l'autre (636 Mio constates apres une serie de runs), ce qui rend son
# rapatriement inutilisable et masque les traces du run courant.
$QGA run --shell "del $VMDIR\\WAC.exe.log 2>nul & echo." >/dev/null 2>&1 || true
$QGA run --shell "cd /d $VMDIR && rmdir /s /q out 2>nul & WAC.exe --output=out --events --loglevel=2 > run.log 2>&1" || CODE=$?
$QGA read "$VMDIR\\run.log" "$SORTIE/run.log" >/dev/null || echo "   ⚠️ run.log non rapatrié"

if [[ -f "$SORTIE/run.log" ]] && grep -qaiE 'terminate called|Unhandled exception|Exception non gérée' "$SORTIE/run.log"; then
    echo "   ❌ WAC s'est TERMINÉ EN EXCEPTION — collecte incomplète :"
    grep -aiE -A2 'terminate called|Unhandled exception|Exception non gérée' "$SORTIE/run.log" | sed 's/^/      /'
    ARRET_ANORMAL=1
elif [[ "$CODE" != "0" ]]; then
    echo "   ❌ WAC a rendu le code $CODE — collecte probablement incomplète"
    ARRET_ANORMAL=1
else
    echo "   ✅ WAC est allé au bout (code $CODE)"
fi

echo "== 5. Rapatriement des JSON =="
LISTE=$($QGA run --shell "dir /b $VMDIR\\out\\*.json 2>nul" || true)
if [[ -z "${LISTE// }" ]]; then
  echo "   ⚠️ aucun JSON produit — voir $SORTIE/run.log"
else
  while read -r f; do
    f="${f%$'\r'}"; [[ -z "$f" ]] && continue
    $QGA read "$VMDIR\\out\\$f" "$SORTIE/$f" >/dev/null && echo "   + $f"
  done <<< "$LISTE"
fi

# Manifeste de consigne + son sceau : minuscules, et ce sont eux qui
# identifient les pièces. Sans eux, check-json.py ne peut pas vérifier la
# consigne (les pièces elles-mêmes pèsent des centaines de Mio et restent sur
# le support de collecte).
mkdir -p "$SORTIE/consigne"
for f in MANIFESTE.json MANIFESTE.sha256; do
  $QGA read "$VMDIR\\out\\consigne\\$f" "$SORTIE/consigne/$f" >/dev/null 2>&1 \
    && echo "   + consigne/$f" || echo "   ⚠️ consigne/$f non rapatrié"
done
# Liste des fichiers réellement présents dans la consigne : sans elle, rien ne
# vérifie que chaque pièce est au manifeste. Une pièce ajoutée après le
# scellement passait inaperçue (121 binaires de fournisseurs d'événements).
$QGA run --shell "chcp 65001 >nul & dir /s /b /a-d $VMDIR\\out\\consigne" \
  > "$SORTIE/consigne/LISTE.txt" 2>/dev/null \
  && echo "   + consigne/LISTE.txt" || echo "   ⚠️ liste de la consigne non relevée"

echo "== 6. Contrôle de validité JSON =="
python3 "$ICI/check-json.py" "$SORTIE" || echo "   ⚠️ des JSON sont invalides (voir ci-dessus)"

echo
if [[ "${ARRET_ANORMAL:-0}" == "1" ]]; then
  echo "== ⚠️ ARRÊT ANORMAL DE WAC : les JSON ci-dessus sont PARTIELS =="
fi
echo "== Résultats sur l'hôte : $SORTIE =="
ls -la "$SORTIE" | awk 'NR>1{print "   "$NF"  "$5" o"}'
