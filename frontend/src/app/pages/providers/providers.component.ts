import { Component, computed, inject, OnInit, signal } from '@angular/core';
import { DatePipe, NgTemplateOutlet } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';

import {
  ApiService, Connection, Provider, ProviderDraft,
} from '../../core/api.service';

/** Fiche vierge pour « Ajouter un site ». Les valeurs par défaut sont celles
 *  qui marchent pour la majorité des fournisseurs OAuth2 standard. */
const EMPTY_DRAFT: ProviderDraft = {
  slug: '',
  display_name: '',
  authorization_url: '',
  token_url: '',
  client_id: '',
  client_secret: '',
  default_scopes: '',
  scope_separator: ' ',
  use_pkce: true,
  account_url: '',
  account_label_field: 'login',
  enabled: true,
  notes: '',
};

@Component({
  selector: 'app-providers',
  standalone: true,
  imports: [DatePipe, FormsModule, NgTemplateOutlet],
  templateUrl: './providers.component.html',
  styleUrl: './providers.component.scss',
})
export class ProvidersComponent implements OnInit {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);

  providers = signal<Provider[]>([]);
  connections = signal<Connection[]>([]);
  isVaultAdmin = signal(false);
  loading = signal(true);
  error = signal<string | null>(null);
  notice = signal<string | null>(null);

  /** Slug du site en cours d'édition, '' = aucun, '__new__' = création. */
  editing = signal<string>('');
  draft: ProviderDraft = { ...EMPTY_DRAFT };
  saving = signal(false);

  /** Index des connexions par slug — évite un find() dans le template. */
  private connectionBySlug = computed(() => {
    const map = new Map<string, Connection>();
    for (const c of this.connections()) map.set(c.provider, c);
    return map;
  });

  ngOnInit(): void {
    // Messages renvoyés par le callback (cf. CallbackView) : le navigateur
    // revient ici avec ?connected=<slug> ou ?oauth_error=<message>.
    const params = this.route.snapshot.queryParamMap;
    const connected = params.get('connected');
    const oauthError = params.get('oauth_error');
    if (connected) this.notice.set(`Compte ${connected} relié avec succès.`);
    if (oauthError) this.error.set(oauthError);

    this.reload(() => {
      // ?connect=<slug> : une app tierce nous a envoyé l'utilisateur pour
      // qu'il relie ce site précis — on lance l'aller-retour directement.
      const toConnect = params.get('connect');
      if (toConnect && !this.connectionBySlug().has(toConnect)) {
        this.connect(toConnect, params.get('return_url') ?? undefined);
      }
    });
  }

  private reload(done?: () => void): void {
    this.loading.set(true);
    this.api.getMe().subscribe({
      next: (me) => {
        this.isVaultAdmin.set(me.is_vault_admin);
        this.api.listProviders().subscribe({
          next: (list) => {
            this.providers.set(list);
            this.api.listConnections().subscribe({
              next: (conns) => {
                this.connections.set(conns);
                this.loading.set(false);
                done?.();
              },
              error: () => { this.loading.set(false); },
            });
          },
          error: (err) => {
            this.loading.set(false);
            this.error.set(`Impossible de charger les sites (${err.status ?? 'réseau'}).`);
          },
        });
      },
      error: (err) => {
        this.loading.set(false);
        this.error.set(
          err.status === 403
            ? "Votre compte n'appartient à aucun groupe du lab : demandez à un administrateur de vous en attribuer un."
            : `Authentification impossible (${err.status ?? 'réseau'}).`,
        );
      },
    });
  }

  connectionOf(slug: string): Connection | undefined {
    return this.connectionBySlug().get(slug);
  }

  // ── Utilisateur : relier / délier ─────────────────────────────────────────
  connect(slug: string, returnUrl?: string): void {
    this.error.set(null);
    this.api.authorize(slug, returnUrl).subscribe({
      next: (res) => {
        // Navigation pleine page volontaire : l'écran de consentement du site
        // doit s'afficher à l'utilisateur, pas être chargé en arrière-plan.
        window.location.href = res.authorization_url;
      },
      error: (err) => {
        this.error.set(
          err.error?.detail
          ?? err.error?.[0]
          ?? `Impossible de démarrer la connexion (${err.status ?? 'réseau'}).`,
        );
      },
    });
  }

  disconnect(slug: string): void {
    if (!confirm(
      `Délier ${slug} ?\n\n`
      + "Le jeton est supprimé d'oauth-hub, mais l'autorisation reste active "
      + 'chez le site : révoquez-la aussi depuis votre compte sur ce site si '
      + 'vous voulez couper complètement l\'accès.',
    )) return;

    this.api.disconnect(slug).subscribe({
      next: () => {
        this.notice.set(`Connexion à ${slug} supprimée.`);
        this.reload();
      },
      error: (err) => {
        this.error.set(`Suppression impossible (${err.status ?? 'réseau'}).`);
      },
    });
  }

  // ── Devs : le coffre ──────────────────────────────────────────────────────
  startCreate(): void {
    this.draft = { ...EMPTY_DRAFT };
    this.editing.set('__new__');
  }

  startEdit(provider: Provider): void {
    // `client_secret` repart toujours vide : l'API ne le renvoie jamais, et un
    // champ vide signifie « conserver l'existant » côté sérialiseur.
    this.draft = { ...provider, client_secret: '' };
    this.editing.set(provider.slug);
  }

  cancelEdit(): void {
    this.editing.set('');
    this.draft = { ...EMPTY_DRAFT };
  }

  save(): void {
    const draft = this.draft;
    const isNew = this.editing() === '__new__';
    this.saving.set(true);
    this.error.set(null);

    const request = isNew
      ? this.api.createProvider(draft)
      : this.api.updateProvider(this.editing(), draft);

    request.subscribe({
      next: () => {
        this.saving.set(false);
        this.notice.set(
          isNew ? `Site « ${draft.slug} » créé.` : `Site « ${this.editing()} » mis à jour.`,
        );
        this.cancelEdit();
        this.reload();
      },
      error: (err) => {
        this.saving.set(false);
        this.error.set(this.formatApiError(err));
      },
    });
  }

  remove(provider: Provider): void {
    const count = this.connections().filter(c => c.provider === provider.slug).length;
    if (!confirm(
      `Supprimer définitivement le site « ${provider.display_name} » ?\n\n`
      + 'Les identifiants OAuth déposés et TOUTES les connexions des '
      + 'utilisateurs du lab vers ce site seront supprimés'
      + (count ? ` (dont la vôtre).` : '.'),
    )) return;

    this.api.deleteProvider(provider.slug).subscribe({
      next: () => {
        this.notice.set(`Site « ${provider.slug} » supprimé.`);
        this.reload();
      },
      error: (err) => { this.error.set(this.formatApiError(err)); },
    });
  }

  copy(text: string): void {
    navigator.clipboard?.writeText(text).then(
      () => this.notice.set('URI de rappel copiée.'),
      () => this.error.set('Copie impossible — sélectionnez le texte à la main.'),
    );
  }

  /** DRF renvoie soit {detail}, soit {champ: [messages]} — on aplatit. */
  private formatApiError(err: { status?: number; error?: unknown }): string {
    const body = err.error as Record<string, unknown> | string | undefined;
    if (typeof body === 'string') return body;
    if (body && typeof body === 'object') {
      if ('detail' in body) return String(body['detail']);
      const parts: string[] = [];
      for (const [field, messages] of Object.entries(body)) {
        parts.push(`${field} : ${Array.isArray(messages) ? messages.join(', ') : messages}`);
      }
      if (parts.length) return parts.join(' — ');
    }
    return `Erreur ${err.status ?? 'réseau'}.`;
  }
}
