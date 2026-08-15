// Fichier chargé avant le démarrage de l'application Angular.
// Modifiable sans recompiler (remplacer les valeurs au déploiement).
// NOTE: Ce fichier est remplacé au démarrage du container par nginx-entrypoint.sh
window.__env = {
  keycloakUrl:      'http://localhost:8080',
  keycloakRealm:    'ssolab',
  keycloakClientId: 'oauth-hub',
  appUrl:           'http://localhost:4215',
  apiUrl:           'http://localhost:8100',
};
