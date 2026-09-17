#pragma once

/*  event_messages.h — MESSAGE EN CLAIR D'UN ÉVÉNEMENT, SANS L'API DU SYSTÈME.
 *
 *  CE QUE CE MODULE REMPLACE. `EvtFormatMessage` rendait la phrase lisible d'un
 *  événement en allant chercher, dans le fichier de ressources du fournisseur,
 *  le modèle de texte correspondant. C'était le dernier service rendu par
 *  l'API : la lecture hors ligne des journaux donnait tout SAUF ce texte, absent
 *  pour environ un événement sur sept (14 046 sur 102 627 mesurés).
 *
 *  CE QU'IL FAUT RÉUNIR, et où chaque pièce se trouve :
 *
 *    le GUID du fournisseur            dans l'événement lui-même
 *    le chemin de son fichier          ruche SOFTWARE, sous
 *                                      WINEVT\Publishers\{guid}
 *    l'identifiant de message          ressource WEVT_TEMPLATE du fichier
 *    le modèle de phrase               ressource MESSAGETABLE — non pas du
 *                                      fichier lui-même, mais de son satellite
 *                                      <langue>\<nom>.mui sur un système localisé
 *    les valeurs à insérer             données de l'événement
 *
 *  EXTRACTION À LA DEMANDE. Ces fichiers de ressources ne font pas partie des
 *  artefacts : ce sont des binaires système quelconques, et il y en a près d'un
 *  millier de déclarés. Les extraire tous coûterait des centaines de mégaoctets
 *  pour des fournisseurs dont la plupart n'ont produit aucun événement. Chaque
 *  fichier est donc extrait au moment où un événement le réclame, une seule
 *  fois, par lecture brute NTFS — comme tout le reste. Il rejoint la consigne,
 *  y est identifié par ses empreintes, puis est recopié dans le répertoire de
 *  travail avant d'être lu.
 *
 *  Un fournisseur dont le fichier est introuvable ou illisible est retenu comme
 *  tel : on ne réessaie pas à chaque événement, et le rapport le consigne.
 */

#include <windows.h>
#include <string>
#include <vector>

/*! Prépare la résolution des messages.
*  À appeler une fois avant la collecte des événements. Sans cet appel, les
*  messages ne sont pas résolus et la collecte se poursuit normalement.
*/
void MessagesInitialiser();

/*! Message en clair d'un événement.
*
*  @param guidFournisseur GUID du fournisseur, « {…} » ; vide si l'événement ne
*         le porte pas — le message est alors introuvable et la fonction rend
*         une chaîne vide
*  @param identifiantEvenement identifiant de l'événement
*  @param version version du schéma de l'événement
*  @param valeurs données de l'événement, dans l'ordre : ce sont elles qui
*         remplissent les marques %1 %2 … du modèle
*  @return la phrase, ou une chaîne vide si elle n'a pas pu être reconstituée
*/
std::wstring MessageEvenement(const std::wstring& guidFournisseur,
                              uint16_t identifiantEvenement,
                              uint8_t version,
                              const std::vector<std::wstring>& valeurs);

/*! Bilan, pour le journal et le rapport.
*  @param fournisseurs nombre de fournisseurs dont les ressources ont été lues
*  @param echecs nombre de fournisseurs dont le fichier n'a pas pu être lu
*  @param resolus nombre de messages effectivement reconstitués
*  @param octets volume extrait pour ces ressources
*/
void MessagesBilan(size_t* fournisseurs, size_t* echecs,
                   unsigned long long* resolus, unsigned long long* octets);

/*! Libère les ressources chargées. */
void MessagesLiberer();
