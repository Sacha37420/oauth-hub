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

## Lot 2 — Polices en chemin relatif   ·   statut : livré
**Objectif :** les polices Foyer se chargent.
**Constat [C] :** `styles.scss:3-11` utilise `url("/assets/fonts/…")`, et `https://<domaine>/assets/fonts/…` répond 404.
**Tâches :**
- [x] `url("assets/fonts/…")`, comme dans storage et app-builder
**Tests à passer avant de clore le lot :**
- [x] Les URL du CSS compilé sont relatives et répondent 200 ; police chargée en navigateur ; cloisonnement 3/3 — vérifié le 2026-11-01 (lab-runner, `e2e_member`)
**Vérifié le :** 2026-11-01 — non déployé. Image `oauth-hub-frontend:candidat` : CSS compilé en `url("./media/…woff2")` (relatif). 200 en service et navigateur : après déploiement.
Statut passé à « livré » le 2026-11-08 (relecture de nuit) : tâche et test cochés, test en navigateur fait le 2026-11-01 (commit `271ec72`), mis en service le même jour (section « Mise en service » plus bas).

## Lot 3 — Référence d'API complète   ·   statut : livré
**Objectif :** une app consommatrice trouve tout dans le README.
**Constat [C] :**
- La référence (`README.md:570-588`) ne liste pas `/api/trusted-clients/` et ne mentionne pas le 403
  « site désactivé ».
- Elle dit « devs » pour l'écriture d'un site, désormais réservée à l'interface.
- Elle renvoie vers `/api/docs/`, en 404 hors DEBUG (l. 590).
- § Tests ne donne pas la commande backend.
**Tâches :**
- [x] Corriger ces cinq points (travail de nuit du 2026-11-08 : routes `/api/trusted-clients/`, 403
  « site désactivé », écriture « depuis l'interface d'oauth-hub » (`WritableFromHubOnly`), `/api/docs/`
  en DEBUG seulement, commande des tests backend ; en plus : `OAUTH_HUB_FRONTEND_PUBLIC_URL` ajoutée
  aux variables, « sauvegarde de `devdb` » → base `lab`)
**Tests à passer avant de clore le lot :**
- [x] Relecture contre `api/urls.py`
**Vérifié le :** 2026-11-08 — relecture de la référence contre `backend/api/urls.py` (routeur `providers`
et `trusted-clients`, routes explicites), `backend/api/views.py` (`TokenView`, 403 l. 544),
`backend/api/permissions.py` (`WritableFromHubOnly`), `backend/config/urls.py:28` (DEBUG),
`backend/config/settings.py:107-138`. Documentation seule, aucun code changé.

## Lot 4 — Durcissement front et jetons courts   ·   statut : en cours
**Objectif :** gabarit front aligné (T3) ; Ⓟ jetons GitHub à durée limitée.
**Tâches :**
- [x] `tokenBases()` ; `redirectUri` limité à l'origine et au préfixe ; PKCE (chantier failles, I2) ; ports liés à `${LAB_BIND_ADDR:-127.0.0.1}` (I1)
- [ ] Ⓟ GitHub App plutôt qu'OAuth App : les jetons d'une OAuth App n'expirent pas (`README.md:645-668`)
- [ ] Ⓟ Pour un site désactivé, le statut garde `connected: true` : à garder ou à changer
- [ ] Pages `home` et `profile` du gabarit : à fusionner ou à retirer
**Tests à passer avant de clore le lot :**
- [x] Connexion et lien direct en navigateur ; aucun jeton envoyé vers une autre origine (`page.route`) — vérifié le 2026-11-01 (lab-runner, `e2e_member`)
**Vérifié le :** 2026-11-01 — non déployé (première tâche seulement). `bash chantiers/tests/essai.sh oauth-hub` : 98 tests OK ; image `oauth-hub-frontend:candidat` construite (`S256` dans le bundle) ; `docker compose config` : `host_ip: 127.0.0.1`.

## Mise en service — chantier « failles » (2026-11-01)
Les mentions « non déployé » ci-dessus datent d'avant cette mise en service. Image construite pendant
que l'ancienne tournait, `scripts/app-test.sh` : 98 tests OK, puis `up -d --no-build` ; ports
publiés sur `127.0.0.1` ; client Keycloak passé en PKCE S256 exigé, URI de retour réduites à celles de
l'app (`create-app-client.sh --pkce --prune-uris`) ; cloisonnement `lab-runner` 3/3 avant et après le durcissement du client, puis de nouveau 3/3 sur Keycloak 26.8.1.
Restent les vérifications en navigateur réel notées dans les lots (images, coffres de clés, envois).
