/**
 * Configuration injectée au démarrage du conteneur (`assets/env.js`, écrit par
 * `nginx-entrypoint.sh`).
 */
export interface LabEnv {
  keycloakUrl?: string;
  keycloakRealm?: string;
  keycloakClientId?: string;
  appUrl?: string;
  apiUrl?: string;
}

export function labEnv(): LabEnv {
  return (window as unknown as { __env?: LabEnv }).__env ?? {};
}

/** Base de l'API d'oauth-hub (`…/oauth-hub-api`), sans barre finale. */
export function apiUrl(): string {
  return (labEnv().apiUrl ?? 'http://localhost:8100').replace(/\/+$/, '');
}

/**
 * Les SEULES adresses auxquelles le jeton de l'utilisateur est joint
 * (`auth.interceptor.ts`, `token-scope.ts`) : l'API d'oauth-hub. Le navigateur
 * n'appelle aucune autre API par HttpClient ; l'écran de consentement du site
 * externe est une navigation pleine page (`window.location.href`), qui ne passe
 * pas par l'intercepteur.
 */
export function tokenBases(): string[] {
  return [apiUrl()];
}
