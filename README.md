# oauth-hub — coffre d'identifiants OAuth et courtier de jetons du lab

`oauth-hub` centralise les identifiants OAuth2 des **sites** externes (GitHub,
GitLab, Google…) et distribue, aux applications autorisées, un jeton **au nom
de l'utilisateur connecté**.

Deux problèmes qu'il résout, et qui expliquent toutes les décisions de ce
document :

1. **Les identifiants appartiennent au site, pas à l'application.** Avant, chaque
   app qui voulait parler à GitHub devait enregistrer sa propre application
   OAuth et détenir son propre `client_secret`. Dix apps = dix secrets à créer,
   à faire tourner et à ne pas laisser fuir. Ici : **une** application OAuth est
   enregistrée par site, et toutes les apps du lab s'en servent.
2. **Une app consommatrice ne voit jamais de secret.** Elle présente le jeton
   Keycloak de son utilisateur et reçoit en échange le jeton du site. Le
   `client_secret` ne quitte jamais `oauth-hub`.

---

## Vocabulaire

| Terme | Ce que c'est |
|---|---|
| **Site** (`Provider`) | Un fournisseur OAuth2 : `github`, `gitlab`, `google`… Porte les identifiants et les URLs. Identifié par un **slug** stable. |
| **Connexion** (`Connection`) | Le jeton d'**un utilisateur** du lab pour **un site**. Une par couple (site, personne). |
| **App consommatrice** | Toute application — du lab ou non — qui demande le jeton amont d'un utilisateur. Identifiée par son `client_id` Keycloak. |
| **Dev** | Membre du groupe `developers` : la seule population qui dépose ou modifie les identifiants d'un site. |

---

## Comment ça marche

```
                    ┌──────────────────────────────────────────┐
                    │  oauth-hub                               │
   1. « donne-moi   │                                          │
      le jeton      │   Provider  github                       │
      GitHub de     │     client_id / client_secret  (chiffré) │
      cet user »    │     authorization_url / token_url        │
  ┌───────────────► │                                          │
  │  Bearer <JWT    │   Connection  (github, alice@…)          │
  │  Keycloak>      │     access_token               (chiffré) │
  │                 └───────────────┬──────────────────────────┘
  │                                 │
┌─┴──────────────┐                  │ 3. échange code ↔ jeton
│ App            │                  │    (client_secret, jamais exposé)
│ consommatrice  │                  ▼
│ (lab ou        │            ┌──────────┐
│  bureau)       │            │  GitHub  │
└────────────────┘            └──────────┘
         ▲                          ▲
         │ 2a. si pas de connexion :│ 2b. l'utilisateur autorise
         │     409 + connect_url    │     dans son navigateur
         └──────────────────────────┘
```

Le point de sécurité central : le retour du site (`/api/callback/<slug>/`) arrive
sur un navigateur **sans jeton Keycloak** — c'est nécessairement une requête
anonyme. Ce qui tient lieu d'authentification est le `state` : aléatoire, à usage
unique, valable 10 minutes, créé par une requête authentifiée et porteur de
l'identité de la personne qui a démarré le flux. Sans lui, n'importe qui pourrait
faire déposer son jeton GitHub dans le compte d'un autre.

---

## ⚠ Les trois URI de rappel — ne pas les confondre

Cette app est faite pour des **applications qui tournent côté client** (outils de
bureau lancés sur le poste de l'utilisateur). Il y a donc trois URI de rappel
dans le montage, et **deux sur trois sont en boucle locale**. Les confondre est
l'erreur qui fait perdre le plus de temps.

| # | URI | Enregistrée où | Valeur | Boucle locale ? |
|---|---|---|---|---|
| 1 | **Callback du fournisseur** | chez GitHub / GitLab / Google | `https://<DOMAIN>/oauth-hub-api/api/callback/<slug>/` | **non — jamais** |
| 2 | **Redirect URI Keycloak** | client Keycloak de votre app | `http://127.0.0.1:8765/callback` | **oui** |
| 3 | **`return_url`** | passée en paramètre, rien à enregistrer | `http://127.0.0.1:8765/oauth-hub-done` | **oui** |

### Pourquoi la n°1 n'est pas — et ne peut pas être — en `localhost`

C'est la question qui revient toujours, alors voici la réponse en entier.

Le fournisseur renvoie un **code d'autorisation**, pas un jeton. Pour le
transformer en jeton, il faut le présenter avec le `client_secret` du site. Si le
fournisseur renvoyait ce code sur `http://127.0.0.1:8765/…`, c'est **votre
application de bureau** qui le recevrait — et elle devrait alors détenir le
`client_secret` pour l'échanger. Autrement dit, il faudrait distribuer le secret
du lab dans chaque poste client, ce qui supprime la seule raison d'être de cette
app.

En envoyant le code sur `oauth-hub`, le secret ne quitte jamais le serveur.
L'application cliente, elle, ne voit passer qu'un jeton déjà échangé, sur les
URI n°2 et n°3 — toutes deux en boucle locale, sur son propre poste.

> Corollaire pratique : **une seule** URI est à enregistrer chez le fournisseur,
> pour tout le lab. Vous n'avez rien à y déclarer quand vous écrivez une nouvelle
> application cliente.

### Ce que voit une application cliente

Les deux URI en boucle locale sont **à vous** : c'est votre application qui ouvre
un petit serveur HTTP sur le port de son choix (8765 dans nos exemples) le temps
de l'aller-retour, puis le referme.

- **n°2** sert à l'authentification **sur le lab** (Keycloak) : c'est là que vous
  récupérez le jeton Keycloak, par authorization code + PKCE S256.
- **n°3** sert au retour **d'`oauth-hub`** après que l'utilisateur a autorisé le
  site externe : elle vous prévient que la connexion est établie et que vous
  pouvez redemander le jeton.

Elles peuvent partager le même port et le même serveur, avec deux chemins
différents — c'est ce que fait l'exemple complet plus bas.

Seules les adresses `127.0.0.1`, `[::1]` et `localhost` sont acceptées en
`return_url`, en plus du domaine du lab. Toute autre valeur est refusée
(`400`) : un endpoint de retour qui redirige vers une URL arbitraire fournie par
l'appelant est un tremplin de hameçonnage.

---

# Partie 1 — Pour les devs : déposer les identifiants d'un site

Tout se fait depuis l'interface : **`https://<DOMAIN>/oauth-hub/` → Sites OAuth**.
Aucun identifiant de site ne vit dans un `.env` ni dans le dépôt.

## Enregistrer une application OAuth chez le fournisseur

Exemple avec GitHub — la démarche est la même ailleurs, seuls les libellés changent.

1. Ouvrez la fiche du site dans `oauth-hub` et **copiez l'URI de rappel** affichée
   en bas de la fiche. Elle vaut :

   ```
   https://<DOMAIN>/oauth-hub-api/api/callback/github/
   ```

   Elle est calculée depuis `DOMAIN`, jamais codée en dur. Ne la recopiez pas de
   mémoire : le fournisseur la revérifie caractère par caractère à l'échange du
   code, et une différence d'un `/` fait échouer la connexion avec un message
   généralement inutile.

   > ⚠ C'est l'URI **n°1** du tableau ci-dessus : celle du serveur, **jamais** une
   > adresse `localhost`, même si les applications qui consommeront ce site
   > tournent sur le poste des utilisateurs. Mettre une boucle locale ici
   > obligerait à distribuer le `client_secret` sur chaque poste.

2. Sur GitHub : **Settings → Developer settings → OAuth Apps → New OAuth App**.
   - *Application name* : ce que verront les utilisateurs du lab au moment
     d'autoriser (« Lab Sacha », par exemple).
   - *Homepage URL* : `https://<DOMAIN>/oauth-hub/`
   - *Authorization callback URL* : **exactement** l'URI copiée à l'étape 1.

3. GitHub affiche un **Client ID**, puis un **Client Secret** après avoir cliqué
   sur « Generate a new client secret ». Le secret n'est montré qu'une fois.

4. Retour dans `oauth-hub` → **Modifier** sur la fiche du site → collez le
   Client ID et le Client Secret → **Enregistrer**.

La pastille passe de « À configurer » à « Non relié » : le site est désormais
connectable par tout le lab.

## Ajouter un site qui n'est pas pré-rempli

Trois sites sont pré-remplis (GitHub, GitLab, Google) **sans identifiants** —
seules les URLs, le séparateur de portées et le support PKCE le sont, parce que
c'est la partie qui se recopie mal. Pour un autre fournisseur, **+ Ajouter un
site** et renseignez :

| Champ | Ce qu'il faut y mettre |
|---|---|
| **Slug** | Identifiant court, stable, en minuscules. Il entre dans l'URL de l'API (`/api/providers/<slug>/token/`), donc **les apps consommatrices en dépendent** : non modifiable après création. |
| **Nom affiché** | Ce que voient les utilisateurs. |
| **URL d'autorisation** | Où le navigateur est envoyé (`.../oauth/authorize`). |
| **URL de jeton** | Où le code est échangé (`.../oauth/token`). |
| **Client ID / Client Secret** | Fournis par le site à l'enregistrement de l'application. |
| **Portées par défaut** | Séparées par des espaces, **quel que soit** le format attendu par le site — la conversion est faite au moment de l'appel. |
| **Séparateur de portées** | Espace pour GitHub/GitLab/Google. Virgule pour quelques sites anciens. |
| **PKCE S256** | À cocher si le site le supporte. **Décochez pour une OAuth App GitHub** : elle ne le supporte pas et l'autorisation échouerait. |
| **URL de profil** | Facultatif, purement cosmétique : sert à afficher *quel* compte l'utilisateur a relié (`https://api.github.com/user`). |
| **Champ du libellé** | Le champ JSON à lire dans la réponse ci-dessus (`login`, `email`…). |

## Modifier un secret

Le champ **Client secret** est en écriture seule : l'API ne le renvoie jamais et
l'interface ne peut donc pas le réafficher. Un secret qu'on peut relire est un
secret qui finit dans une capture d'écran.

- **Laisser le champ vide** conserve le secret enregistré. C'est ce qui permet de
  corriger une URL ou une portée sans avoir le secret sous la main.
- **Saisir une valeur** la remplace.

## Supprimer un site

Supprime les identifiants **et, en cascade, toutes les connexions du lab vers ce
site** : chaque utilisateur devra recommencer. L'interface le rappelle avant de
confirmer. Pour désactiver temporairement, décochez plutôt **Site actif**.

---

# Partie 2 — Pour les applications qui délèguent leur OAuth2

## Contrat d'interface

| Élément | Valeur |
|---|---|
| Issuer Keycloak | `https://<DOMAIN>/auth/realms/ssolab` |
| Client ID (exemple natif) | `storage-analysis` — public, **sans secret** |
| Flux d'authentification | authorization code + **PKCE S256** (client natif) ou celui déjà en place pour une app web du lab |
| Redirect URI Keycloak *(boucle locale)* | `http://127.0.0.1:8765/callback` — URI **n°2** |
| Base de l'API | `https://<DOMAIN>/oauth-hub-api` |
| Jeton amont | `GET /api/providers/<slug>/token/`, en-tête `Authorization: Bearer <jeton Keycloak>` |
| Réponse | `{"access_token", "token_type", "scope", "expires_at"}` |
| Pas encore relié | `409` + `{"detail", "provider", "connect_url"}` |
| `return_url` *(boucle locale, facultatif)* | `http://127.0.0.1:8765/oauth-hub-done` — URI **n°3** |
| Callback fournisseur | `https://<DOMAIN>/oauth-hub-api/api/callback/<slug>/` — URI **n°1**, côté serveur, **rien à faire pour vous** |

## Étape 0 — se faire autoriser (obligatoire)

Une app n'est pas autorisée par défaut. Son `client_id` Keycloak doit figurer
dans la page **« Apps autorisées »** de l'interface : un dev (membre d'un groupe
de `OAUTH_HUB_ADMIN_GROUPS`) l'y ajoute, ça prend effet à la requête suivante.
Ni redémarrage, ni accès à l'hôte, ni changement côté Keycloak — c'est le claim
`azp` du jeton que l'utilisateur présente déjà qui est comparé à cette liste.

> **Ce que vous accordez en ajoutant une ligne ici** : cette app pourra obtenir le
> jeton **brut** du site pour chacun de ses utilisateurs, et agir sur GitHub (ou
> ailleurs) en leur nom, avec toutes les portées accordées. C'est pour ça que la
> liste est tenue app par app, explicitement, et **jamais ouverte au realm** —
> le realm expose `admin-cli` en client public avec password grant, donc « tout
> compte authentifié » signifierait « tout compte du lab, depuis n'importe où ».

Quatre garde-fous ne sont éditables par personne, dev compris :

| Garde-fou | Pourquoi |
|---|---|
| Le client d'`oauth-hub` est autorisé **en dur** | Une liste vidée par erreur verrouillerait l'interface qui sert à la réparer. |
| `admin-cli` & consorts sont **refusés** | Clients intégrés du realm, jamais des apps du lab. Le refus est appliqué à la vérification, pas seulement à la saisie : une ligne insérée directement en base reste inerte. |
| **Aucun cache** de la liste | Une révocation prend effet à la requête suivante. Un cache mémoire serait par processus gunicorn, donc une révocation resterait partiellement sans effet, silencieusement. |
| La liste ne s'édite **que depuis l'interface d'oauth-hub** | Une app déjà autorisée détient les jetons amont des utilisateurs qui s'en servent ; avec le jeton d'un dev, elle pourrait sinon s'ajouter des complices et gagner ceux de tout le lab. Lecture ouverte, écriture non. |

`KEYCLOAK_TRUSTED_CLIENTS` (`oauth-hub/.env`) **n'est plus lue à l'exécution** :
elle n'a servi qu'une fois, comme graine de la migration qui a repris la liste
existante. Éditer le `.env` n'autorise ni ne révoque plus rien.

> **Suspendre plutôt que révoquer.** Une fiche décochée refuse les appels
> immédiatement mais garde sa description et sa trace de modification — le bon
> geste pour une coupure temporaire ou un doute. « Révoquer » supprime la fiche.

## Le parcours complet, côté app consommatrice

```
1.  GET /api/providers/github/token/     →  409 {connect_url}
2.  ouvrir connect_url dans un navigateur
    (l'utilisateur s'authentifie sur le lab, puis autorise GitHub)
3.  GET /api/providers/github/token/     →  200 {access_token}
4.  appeler l'API GitHub avec ce jeton
```

L'étape 2 n'a lieu **qu'une fois par utilisateur et par site** : la connexion
persiste, et toutes les apps la partagent.

### Exemple complet — application de bureau en Python

C'est le cas d'usage principal de cette app, et celui de `storage_analysis` :
client public natif, **les deux redirections en boucle locale**, PKCE S256,
aucun secret embarqué.

Le client Keycloak est déjà créé :

```bash
bash scripts/create-app-client.sh storage-analysis --public --no-env \
  --native-redirect 'http://127.0.0.1:8765/callback' \
  --require-group developers --no-wan
```

`--no-env` parce que cette application vit **hors** de `dev/` : sans lui, le
script créerait un dossier vide avec un `.env` orphelin que rien ne déploierait.
Les valeurs à recopier dans le client Python sont affichées en fin d'exécution.

Le client obtenu a **une seule** redirect URI (`http://127.0.0.1:8765/callback`,
sans joker) et exige PKCE S256.

#### Le serveur de boucle locale

Les deux retours (Keycloak et `oauth-hub`) arrivent sur le même port, sur deux
chemins différents. Un seul serveur éphémère suffit :

```python
"""Serveur de boucle locale : capte les retours du navigateur, puis se ferme."""
import http.server
import threading
import urllib.parse

LOOPBACK_PORT = 8765          # doit correspondre à l'URI enregistrée dans Keycloak
REDIRECT_URI = f"http://127.0.0.1:{LOOPBACK_PORT}/callback"       # URI n°2
RETURN_URL   = f"http://127.0.0.1:{LOOPBACK_PORT}/oauth-hub-done" # URI n°3


_done = threading.Event()


class _Catcher(http.server.BaseHTTPRequestHandler):
    received: dict = {}
    wanted_path: str = "/callback"

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != type(self).wanted_path:
            self.send_error(404)
            return
        type(self).received = dict(urllib.parse.parse_qsl(parsed.query))
        _done.set()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            "<h1>C'est bon.</h1><p>Vous pouvez fermer cet onglet et "
            "revenir à l'application.</p>".encode()
        )

    def log_message(self, *args):
        pass  # pas de bruit dans la console de l'application


def wait_for_redirect(path: str) -> dict:
    """Ouvre le port, attend UN retour du navigateur sur `path`, referme."""
    _Catcher.received, _Catcher.wanted_path = {}, path
    _done.clear()
    # 127.0.0.1 et non 0.0.0.0 : le port ne doit jamais être joignable depuis le
    # réseau, sinon un voisin pourrait intercepter le code d'autorisation.
    server = http.server.HTTPServer(("127.0.0.1", LOOPBACK_PORT), _Catcher)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _done.wait(timeout=300)          # l'utilisateur peut mettre du temps
    server.shutdown()
    server.server_close()
    if not _Catcher.received:
        raise TimeoutError("aucun retour du navigateur sur la boucle locale")
    return _Catcher.received
```

#### 1. S'authentifier sur le lab (URI n°2, boucle locale)

Authorization code + PKCE S256 contre Keycloak, sans aucun secret :

```python
import base64, hashlib, secrets, urllib.parse, webbrowser, requests

ISSUER    = "https://<DOMAIN>/auth/realms/ssolab"
CLIENT_ID = "storage-analysis"


def keycloak_login() -> str:
    verifier  = secrets.token_urlsafe(64)[:128]
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    state = secrets.token_urlsafe(32)

    params = {
        "client_id": CLIENT_ID, "response_type": "code",
        "redirect_uri": REDIRECT_URI, "scope": "openid profile email",
        "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    webbrowser.open(
        f"{ISSUER}/protocol/openid-connect/auth?{urllib.parse.urlencode(params)}"
    )

    answer = wait_for_redirect("/callback")
    if answer.get("state") != state:      # anti-CSRF : ne jamais sauter ce test
        raise RuntimeError("state inattendu — connexion abandonnée")

    tokens = requests.post(
        f"{ISSUER}/protocol/openid-connect/token",
        data={
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "code": answer["code"], "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,      # ce qui remplace le client_secret
        }, timeout=15,
    )
    tokens.raise_for_status()
    return tokens.json()["access_token"]
```

#### 2. Obtenir le jeton du site (URI n°3, boucle locale)

```python
HUB = "https://<DOMAIN>/oauth-hub-api"


def site_token(keycloak_token: str, slug: str = "github") -> str:
    """Rend un jeton du site, en guidant l'utilisateur s'il n'a rien relié."""
    headers = {"Authorization": f"Bearer {keycloak_token}"}
    url = f"{HUB}/api/providers/{slug}/token/"

    response = requests.get(url, params={"return_url": RETURN_URL},
                            headers=headers, timeout=15)

    if response.status_code == 409:
        # Pas encore relié. `connect_url` porte déjà notre RETURN_URL : une fois
        # l'autorisation donnée, oauth-hub renvoie le navigateur sur notre port
        # local, ce qui nous débloque sans faire patienter l'utilisateur sur un
        # « appuyez sur Entrée ».
        webbrowser.open(response.json()["connect_url"])
        wait_for_redirect("/oauth-hub-done")
        response = requests.get(url, headers=headers, timeout=15)

    response.raise_for_status()
    return response.json()["access_token"]


if __name__ == "__main__":
    token = site_token(keycloak_login())
    me = requests.get("https://api.github.com/user",
                      headers={"Authorization": f"Bearer {token}"}).json()
    print("Connecté à GitHub en tant que", me["login"])
```

Sans `return_url`, tout fonctionne aussi : `oauth-hub` renvoie simplement le
navigateur sur sa propre page, et votre application doit alors demander à
l'utilisateur de revenir vers elle. Le passer rend l'enchaînement automatique.

---

## Ce que contient le retour sur `127.0.0.1`

Le retour n'est pas un simple « c'est fait » : `oauth-hub` y joint tout ce dont
une application cliente a besoin pour la suite, **pour qu'elle n'ait à coder en
dur ni notre domaine, ni notre préfixe d'URL, ni les adresses de renouvellement**.

### En cas de succès

```
http://127.0.0.1:8765/oauth-hub-done
    ?connected=github
    &provider=github
    &token_url=https://<DOMAIN>/oauth-hub-api/api/providers/github/token/
    &status_url=https://<DOMAIN>/oauth-hub-api/api/providers/github/status/
    &issuer=https://<DOMAIN>/auth/realms/ssolab
    &auto_renew=true
    &scope=read:user+repo
    &expires_at=2026-08-15T23:38:09.807143+00:00
    &account=alice-gh
```

| Paramètre | Toujours présent | Ce que c'est |
|---|---|---|
| `connected` / `provider` | oui | Le slug du site relié. Les deux portent la même valeur : `connected` se lit comme un signal de succès, `provider` comme une donnée. |
| `token_url` | oui | **Où redemander le jeton.** C'est la valeur qui rend l'application indépendante de notre routage. |
| `status_url` | oui | Où vérifier l'état sans faire transiter de jeton (pour un affichage). |
| `issuer` | oui | L'issuer Keycloak, pour renouveler **votre** jeton de lab (`{issuer}/protocol/openid-connect/token`). |
| `auto_renew` | oui | `true` : `oauth-hub` détient un `refresh_token` et renouvellera le jeton amont tout seul. `false` : soit le jeton est durable (OAuth App GitHub), soit il faudra une nouvelle autorisation à l'expiration. |
| `scope` | oui | Les portées réellement accordées — pas celles demandées. À vérifier si votre application en exige une précise : l'utilisateur a pu en refuser. |
| `expires_at` | **non** | Absent quand le site ne déclare aucune expiration (cas de GitHub). |
| `account` | **non** | Libellé du compte relié (`login` GitHub…), absent si le site n'expose pas de profil. |

> ⚠ **Le jeton n'est jamais dans cette URL, et n'y sera jamais.** Une URL ouverte
> dans un navigateur atterrit dans l'historique, peut fuiter par l'en-tête
> `Referer`, et traverse les journaux de tout serveur local qui l'a vue passer.
> Le jeton se récupère sur `token_url`, par un appel authentifié — un canal que
> votre application contrôle de bout en bout. Tous les paramètres ci-dessus sont
> des métadonnées non sensibles.

### En cas d'échec

```
http://127.0.0.1:8765/oauth-hub-done
    ?oauth_error=Requête+de+connexion+expirée+—+recommencez.
    &oauth_error_code=expired_state
    &provider=github
```

`oauth_error` est un message en français, destiné à être **affiché** ;
`oauth_error_code` est stable et destiné à être **testé** — ne faites jamais
correspondre le texte du message, il peut être reformulé.

| `oauth_error_code` | Quand | Que faire |
|---|---|---|
| `unknown_state` | `state` inconnu ou déjà consommé (retour rejoué, double clic) | Recommencer la connexion |
| `expired_state` | Plus de 10 minutes entre le départ et le retour | Recommencer |
| `provider_mismatch` | Le site du callback ne correspond pas à la demande | Recommencer ; si ça persiste, prévenir un dev |
| `provider_refused` | L'utilisateur a refusé, ou le site a renvoyé une erreur | Ne pas réessayer en boucle : c'est une décision de l'utilisateur |
| `no_code` | Le site n'a renvoyé aucun code d'autorisation | Recommencer |
| `exchange_failed` | L'échange code ↔ jeton a échoué (identifiants du site faux, site injoignable) | **Prévenir un dev** : c'est une erreur de configuration, réessayer n'y changera rien |

`provider` est absent si l'erreur est survenue avant qu'on ait pu identifier la
demande (`unknown_state`).

### L'exploiter

```python
def handle_return(params: dict) -> str:
    """Traite le retour d'oauth-hub et rend l'URL de renouvellement du jeton."""
    if "oauth_error" in params:
        code = params.get("oauth_error_code", "error")
        if code == "exchange_failed":
            raise RuntimeError(
                f"Configuration du site cassée côté lab : {params['oauth_error']}"
            )
        raise RuntimeError(params["oauth_error"])   # cas rattrapables

    if not params.get("auto_renew") == "true" and not params.get("expires_at"):
        pass          # jeton durable : rien à prévoir (cas GitHub)

    # À mémoriser plutôt que codé en dur : l'app suit le lab s'il déménage.
    return params["token_url"]
```

En pratique une application n'a **rien à faire du renouvellement amont** :
elle rappelle `token_url` quand elle a besoin d'un jeton, et `oauth-hub`
renouvelle en interne si nécessaire. `auto_renew` et `expires_at` ne servent qu'à
afficher une information juste à l'utilisateur, ou à anticiper le fait qu'une
nouvelle autorisation sera un jour nécessaire.

### Exemple — app Angular du lab

```ts
// Le jeton Keycloak est déjà posé par l'intercepteur de l'app.
this.http.get<{ access_token: string }>(
  'https://<DOMAIN>/oauth-hub-api/api/providers/github/token/',
).subscribe({
  next: (res) => this.callGithub(res.access_token),
  error: (err) => {
    if (err.status === 409) window.location.href = err.error.connect_url;
  },
});
```

Toutes les apps du lab partagent le même `DOMAIN` (seul le chemin Caddy change) :
l'appel est **same-origin**, il n'y a aucun CORS à configurer.

### Renouvellement — qui renouvelle quoi

Il y a **deux** jetons dans le montage, et ils ne se renouvellent pas au même
endroit. C'est la source de confusion la plus fréquente.

| Jeton | Durée | Qui le renouvelle | L'app est-elle autonome ? |
|---|---|---|---|
| **Keycloak** (votre jeton de lab) | 1 h | **Votre application**, avec le `refresh_token` rendu par Keycloak, contre `{issuer}/protocol/openid-connect/token` | Oui — tant que la session SSO vit (12 h d'inactivité, 24 h maximum). Au-delà, l'utilisateur doit se reconnecter au lab. |
| **Amont** (GitHub, GitLab…) | variable | **`oauth-hub`, tout seul** | Oui, totalement. Votre application ne voit jamais le `refresh_token` amont : il reste chiffré côté serveur. |

Concrètement, côté application consommatrice : **il n'y a rien à implémenter pour
le jeton amont**. Rappelez `token_url` quand vous avez besoin d'un jeton :

- s'il est encore valide, vous le recevez tel quel ;
- s'il a expiré et qu'un `refresh_token` existe, `oauth-hub` le renouvelle avant
  de répondre — l'échange est invisible pour vous (marge de 60 s, pour qu'un
  jeton expirant pendant le trajet réseau ne vous soit jamais servi) ;
- s'il a expiré sans moyen de le renouveler, vous recevez un `409` avec
  `connect_url` : l'utilisateur doit ré-autoriser, il n'y a pas d'alternative.

Le seul cas où l'autonomie s'arrête est donc ce `409` — et, pour GitHub, il
n'arrive jamais du fait de l'expiration, puisque ces jetons sont durables (voir
« Limite connue » plus bas).

### Savoir sans demander le jeton

Pour un simple affichage (« Connecté à GitHub ✓ »), n'appelez pas `…/token/` :
ça ferait transiter et journaliser un jeton pour rien.

```
GET /api/providers/github/status/
→ {"provider", "display_name", "configured", "connected", "scope",
   "account_label", "connect_url"}
```

---

## Référence de l'API

Base : `https://<DOMAIN>/oauth-hub-api`. Tout requiert
`Authorization: Bearer <jeton Keycloak>`, **sauf** le callback.

| Méthode | Chemin | Qui | Rôle |
|---|---|---|---|
| `GET` | `/api/me/` | tous | Identité, groupes, `is_vault_admin` |
| `GET` | `/api/providers/` | tous | Liste des sites (**sans secret**) + `callback_uri` |
| `POST` | `/api/providers/` | devs | Créer un site |
| `PATCH` | `/api/providers/<slug>/` | devs | Modifier (secret vide = inchangé) |
| `DELETE` | `/api/providers/<slug>/` | devs | Supprimer (cascade sur les connexions) |
| `GET` | `/api/connections/` | tous | Mes connexions |
| `DELETE` | `/api/connections/<slug>/` | tous | Délier un site |
| `GET` | `/api/providers/<slug>/authorize/` | tous | Démarre le flux → `{authorization_url}` |
| `GET` | `/api/callback/<slug>/` | **le site** | Retour du fournisseur (anonyme, protégé par `state`) |
| `GET` | `/api/providers/<slug>/token/` | apps de confiance | **Le jeton amont** |
| `GET` | `/api/providers/<slug>/status/` | apps de confiance | Relié ou non, sans transmettre le jeton |

Documentation interactive : `https://<DOMAIN>/oauth-hub-api/api/docs/`.

---

## Sécurité

### Cloisonnement

Les deux verrous habituels du lab s'appliquent (voir `CLAUDE.md`), avec une
nuance propre à cette app :

- **Verrou 1** (flow Keycloak `require-oauth-hub`) et **Verrou 2** (contrôle
  `azp` + `groups` dans `api/authentication.py`) exigent ici l'appartenance à
  **au moins un groupe** du realm, et non à un groupe nommé : tout compte
  réellement rattaché au lab peut relier ses propres comptes externes ; un
  compte fraîchement auto-inscrit, qui n'a aucun groupe, n'accède à rien.
- Concrètement, `--require-group` reçoit la **liste complète** des groupes.

> ⚠ **Maintenance** : créer un nouveau groupe LDAP impose de l'ajouter à
> `oauth-hub/.keycloak-client-opts` **et** à `KEYCLOAK_REQUIRED_GROUPS` dans
> `oauth-hub/.env`, puis de relancer `create-app-client.sh`. Sans ça, les membres
> de ce groupe seront refusés alors qu'ils sont bien rattachés au lab.

L'accès au **coffre** (déposer/modifier un `client_secret`) est un cran au-dessus :
groupe `developers`, réglable via `OAUTH_HUB_ADMIN_GROUPS`.

### Chiffrement au repos

Les `client_secret` des sites et les jetons amont des utilisateurs sont chiffrés
(Fernet) avec `OAUTH_HUB_ENCRYPTION_KEY`, qui ne vit que dans `oauth-hub/.env`.

Ce que ça protège : une fuite de données **froides** — sauvegarde de `devdb`,
volume, dump SQL. C'est ce qui compte ici, parce que cette app écrit dans
l'instance PostgreSQL **partagée** par tout le lab.

Ce que ça ne protège pas, et qu'il ne faut pas se raconter : un attaquant qui
obtient un shell dans le conteneur `oauth-hub-backend` lit la clé dans
l'environnement et déchiffre tout.

> ⚠ `scripts/init-secrets.sh` **ne régénère jamais** cette clé si elle existe
> déjà — contrairement à tous les autres secrets de ce script, qui ne valent que
> pour des volumes neufs. La remplacer rendrait le coffre entier illisible, sans
> reprise possible : il faudrait le vider et redemander à chacun de relier ses
> comptes.

### Ce que cette app concentre

Une seule app détient de quoi agir, au nom de tous les comptes du lab, sur tous
les sites configurés. C'est le prix assumé de la centralisation des identifiants :
ce qui était réparti sur dix apps est ici en un point. Les contreparties déjà en
place : chiffrement au repos, liste blanche explicite des apps consommatrices,
secret jamais relisible, et journalisation de chaque remise de jeton (quelle app,
pour quel utilisateur, pour quel site).

---

## Limite connue — les jetons GitHub n'expirent pas

Une **OAuth App** GitHub délivre un jeton **sans expiration** et sans
`refresh_token`. `oauth-hub` stocke donc, pour chaque utilisateur ayant relié
GitHub, un identifiant durable : la colonne `expires_at` reste `NULL` et
l'interface affiche « aucune — le site délivre un jeton durable ».

Conséquences pratiques :

- Délier un site depuis `oauth-hub` supprime le jeton **de notre côté** seulement.
  L'autorisation reste active chez GitHub tant que l'utilisateur ne la révoque pas
  depuis *Settings → Applications → Authorized OAuth Apps*. L'interface le dit au
  moment de délier.
- Une fuite de la base **et** de la clé de chiffrement donnerait des jetons
  valables indéfiniment.

**Piste d'évolution, non implémentée : passer à une GitHub App.** Elles délivrent
des jetons à durée de vie courte (8 h) avec `refresh_token`, et permettent de
restreindre l'accès dépôt par dépôt au lieu d'accorder la portée `repo` entière.
Le renouvellement automatique est déjà en place dans `oauth-hub` (il sert à GitLab
et Google) : la bascule se ferait donc en changeant l'enregistrement côté GitHub
et les URLs de la fiche, sans toucher au code. Ce n'est pas fait aujourd'hui parce
que l'installation d'une GitHub App impose une étape supplémentaire par compte et
par dépôt, qui n'était pas justifiée pour le premier usage.

---

## Exploitation

### Variables d'environnement propres à l'app

| Clé | Rôle |
|---|---|
| `OAUTH_HUB_ENCRYPTION_KEY` | Clé Fernet du coffre. Générée par `init-secrets.sh`, jamais régénérée. |
| `OAUTH_HUB_ADMIN_GROUPS` | Groupes autorisés à modifier les identifiants (défaut `developers`). |
| `KEYCLOAK_TRUSTED_CLIENTS` | **Graine initiale seulement, plus lue à l'exécution** — les apps autorisées se tiennent dans la page « Apps autorisées ». |
| `OAUTH_HUB_ALLOWED_RETURN_HOSTS` | Hôtes acceptés dans `return_url`. La boucle locale est toujours acceptée en plus. |
| `OAUTH_HUB_BACKEND_PUBLIC_URL` | Base de l'URI de rappel. Déduite de `DOMAIN`, à ne surcharger que pour un déploiement atypique. |

### Dépannage

| Symptôme | Cause la plus fréquente |
|---|---|
| `redirect_uri_mismatch` chez le site | L'URI enregistrée sur le site ne correspond pas à celle affichée sur la fiche. Recopiez-la depuis l'interface. |
| « Requête de connexion inconnue ou déjà utilisée » | `state` expiré (10 min) ou callback rejoué. Recommencez la connexion. |
| `403` « client non autorisé » | Le `client_id` de l'app appelante manque dans la page « Apps autorisées », ou sa fiche y est suspendue. Le message d'erreur donne le `azp` reçu : c'est exactement la valeur à saisir. |
| `403` « au moins un groupe » | Le compte n'a aucun groupe LDAP, ou un groupe récent manque dans `KEYCLOAK_REQUIRED_GROUPS`. |
| « Secret illisible » dans les journaux | `OAUTH_HUB_ENCRYPTION_KEY` a changé depuis le chiffrement. |
| Autorisation refusée par GitHub avec PKCE | Décochez **PKCE S256** sur la fiche : les OAuth Apps GitHub ne le supportent pas. |

### Tests

```bash
docker exec lab-runner sh -c "curl -s -X POST -H 'Content-Type: application/json' \
  -d '{\"app\":\"oauth-hub\"}' http://localhost:4300/run"
```

Une réponse `[]` signifie « aucun test trouvé », jamais « tout va bien ».
