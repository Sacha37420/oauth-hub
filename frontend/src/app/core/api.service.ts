import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

interface EnvWindow {
  __env?: { apiUrl?: string };
}

/** Un site OAuth enregistré dans le coffre. Ne porte JAMAIS le client_secret :
 *  l'API ne le renvoie pas, seulement `has_client_secret`. */
export interface Provider {
  slug: string;
  display_name: string;
  authorization_url: string;
  token_url: string;
  client_id: string;
  has_client_secret: boolean;
  is_configured: boolean;
  default_scopes: string;
  scope_separator: string;
  use_pkce: boolean;
  account_url: string;
  account_label_field: string;
  enabled: boolean;
  notes: string;
  updated_at: string;
  updated_by: string;
  /** URI de rappel à enregistrer côté site — calculée par le backend. */
  callback_uri: string;
}

/** Champs modifiables ; `client_secret` est en écriture seule (vide = inchangé). */
export type ProviderDraft = Partial<Provider> & { client_secret?: string };

export interface Connection {
  provider: string;
  provider_display_name: string;
  scope: string;
  account_label: string;
  expires_at: string | null;
  is_expired: boolean;
  has_refresh_token: boolean;
  created_at: string;
  updated_at: string;
}

export interface Me {
  email: string;
  username: string;
  groups: string[];
  is_vault_admin: boolean;
  client_id: string;
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  private http = inject(HttpClient);

  private get base(): string {
    return (window as unknown as EnvWindow).__env?.apiUrl
      ?? 'http://localhost:8100';
  }

  getMe(): Observable<Me> {
    return this.http.get<Me>(`${this.base}/api/me/`);
  }

  // ── Coffre (lecture : tout le lab ; écriture : devs) ───────────────────────
  listProviders(): Observable<Provider[]> {
    return this.http.get<Provider[]>(`${this.base}/api/providers/`);
  }

  createProvider(draft: ProviderDraft): Observable<Provider> {
    return this.http.post<Provider>(`${this.base}/api/providers/`, draft);
  }

  updateProvider(slug: string, draft: ProviderDraft): Observable<Provider> {
    return this.http.patch<Provider>(`${this.base}/api/providers/${slug}/`, draft);
  }

  deleteProvider(slug: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/api/providers/${slug}/`);
  }

  // ── Mes connexions ────────────────────────────────────────────────────────
  listConnections(): Observable<Connection[]> {
    return this.http.get<Connection[]>(`${this.base}/api/connections/`);
  }

  disconnect(slug: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/api/connections/${slug}/`);
  }

  /** Demande l'URL d'autorisation. Le backend ne redirige pas lui-même :
   *  une 302 sur un `fetch()` serait suivie en arrière-plan et l'écran de
   *  consentement du site ne s'afficherait jamais. */
  authorize(slug: string, returnUrl?: string): Observable<{ authorization_url: string }> {
    const query = returnUrl ? `?return_url=${encodeURIComponent(returnUrl)}` : '';
    return this.http.get<{ authorization_url: string }>(
      `${this.base}/api/providers/${slug}/authorize/${query}`,
    );
  }
}
