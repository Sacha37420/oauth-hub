# Feuille de route — oauth-hub

Ce fichier est lu par une machine : `validate-app.sh` refuse de déployer s'il manque ou s'il ne
contient aucun lot au format ci-dessous, et `app-test.sh` lit la commande de test. Garder les titres
tels quels.

Service du cadriciel, livré avant l'obligation de feuille de route : le Lot 1 résume l'existant.
Les lots suivants viennent de l'analyse du 2026-10-31 (vue d'ensemble : `to_do_global.md` à la
racine du dépôt du lab). [C] constaté, [D] déduit.

## Commande de test
python manage.py test

## Lot 1 — Existant : coffre des sites, liaison des comptes, remise de jetons   ·   statut : livré
**Objectif :** identifiants OAuth2 des sites externes (GitHub, GitLab…), et remise d'un jeton au nom
de l'utilisateur aux apps de la liste blanche (`TrustedClient`, éditée dans l'interface).
**Tâches :**
- [x] Neuf défauts du chantier tests corrigés (`chantiers/tests/rapports/hub-craft.md`) : écriture
  depuis l'interface seulement, slug en lecture seule, `return_url` avec antislash refusée, site désactivé → 403…
**Tests à passer avant de clore le lot :**
- [x] 98 tests backend (`test_flux`, `test_coffre`, `test_jeton`, `test_serrure`) ; `cloisonnement.spec.ts`
**Vérifié le :** 2026-10-31 — relevé par lecture (version en service = `423744f`), tests non rejoués.

## Lot 2 — Polices en chemin relatif   ·   statut : à faire
**Objectif :** les polices Foyer se chargent.
**Constat [C] :** `styles.scss:3-11` utilise `url("/assets/fonts/…")`, et `https://<domaine>/assets/fonts/…` répond 404.
**Tâches :**
- [ ] `url("assets/fonts/…")`, comme dans storage et app-builder
**Tests à passer avant de clore le lot :**
- [ ] Les URL du CSS compilé sont relatives et répondent 200 ; police chargée en navigateur ; cloisonnement 3/3
**Vérifié le :**

## Lot 3 — Référence d'API complète   ·   statut : à faire
**Objectif :** une app consommatrice trouve tout dans le README.
**Constat [C] :**
- La référence (`README.md:570-588`) ne liste pas `/api/trusted-clients/` et ne mentionne pas le 403
  « site désactivé ».
- Elle dit « devs » pour l'écriture d'un site, désormais réservée à l'interface.
- Elle renvoie vers `/api/docs/`, en 404 hors DEBUG (l. 590).
- § Tests ne donne pas la commande backend.
**Tâches :**
- [ ] Corriger ces cinq points
**Tests à passer avant de clore le lot :**
- [ ] Relecture contre `api/urls.py`
**Vérifié le :**

## Lot 4 — Durcissement front et jetons courts   ·   statut : à faire
**Objectif :** gabarit front aligné (T3) ; Ⓟ jetons GitHub à durée limitée.
**Tâches :**
- [ ] `tokenBases()` ; `redirectUri` limité à l'origine et au préfixe ; PKCE
- [ ] Ⓟ GitHub App plutôt qu'OAuth App : les jetons d'une OAuth App n'expirent pas (`README.md:645-668`)
- [ ] Ⓟ Pour un site désactivé, le statut garde `connected: true` : à garder ou à changer
- [ ] Pages `home` et `profile` du gabarit : à fusionner ou à retirer
**Tests à passer avant de clore le lot :**
- [ ] Connexion et lien direct en navigateur ; aucun jeton envoyé vers une autre origine (`page.route`)
**Vérifié le :**
