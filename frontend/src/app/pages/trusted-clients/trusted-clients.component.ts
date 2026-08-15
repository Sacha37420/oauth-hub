import { Component, inject, OnInit, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import {
  ApiService, TrustedClient, TrustedClientDraft,
} from '../../core/api.service';

const EMPTY_DRAFT: TrustedClientDraft = {
  client_id: '',
  description: '',
  enabled: true,
};

/**
 * Page « Apps autorisées » — la liste blanche `azp` du backend, éditable.
 *
 * Ce que cette page accorde tient en une phrase, et elle est écrite en tête de
 * l'écran plutôt que dans ce commentaire : une app autorisée obtient le jeton
 * **brut** du site pour chacun de ses utilisateurs. Toutes les décisions d'UI
 * en découlent — la révocation est à un clic, la fiche permanente d'oauth-hub
 * est affichée au lieu d'être masquée, et rien n'est jamais présenté comme
 * anodin.
 */
@Component({
  selector: 'app-trusted-clients',
  standalone: true,
  imports: [DatePipe, FormsModule],
  templateUrl: './trusted-clients.component.html',
  styleUrl: './trusted-clients.component.scss',
})
export class TrustedClientsComponent implements OnInit {
  private api = inject(ApiService);

  clients = signal<TrustedClient[]>([]);
  isVaultAdmin = signal(false);
  loading = signal(true);
  error = signal<string | null>(null);
  notice = signal<string | null>(null);

  /** client_id en cours d'édition, '' = aucun, '__new__' = création. */
  editing = signal<string>('');
  draft: TrustedClientDraft = { ...EMPTY_DRAFT };
  saving = signal(false);

  ngOnInit(): void {
    this.reload();
  }

  private reload(): void {
    this.loading.set(true);
    this.api.getMe().subscribe({
      next: (me) => {
        this.isVaultAdmin.set(me.is_vault_admin);
        this.api.listTrustedClients().subscribe({
          next: (list) => {
            this.clients.set(list);
            this.loading.set(false);
          },
          error: (err) => {
            this.loading.set(false);
            this.error.set(`Impossible de charger la liste (${err.status ?? 'réseau'}).`);
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

  startCreate(): void {
    this.draft = { ...EMPTY_DRAFT };
    this.editing.set('__new__');
  }

  startEdit(client: TrustedClient): void {
    this.draft = {
      client_id: client.client_id,
      description: client.description,
      enabled: client.enabled,
    };
    this.editing.set(client.client_id);
  }

  cancelEdit(): void {
    this.editing.set('');
    this.draft = { ...EMPTY_DRAFT };
  }

  save(): void {
    const isNew = this.editing() === '__new__';
    this.saving.set(true);
    this.error.set(null);

    // En modification, `client_id` n'est pas envoyé : le backend le refuse en
    // écriture (le changer révoquerait une app et en autoriserait une autre
    // sous couvert de correction) et le champ est affiché en lecture seule.
    const request = isNew
      ? this.api.createTrustedClient(this.draft)
      : this.api.updateTrustedClient(this.editing(), {
        description: this.draft.description,
        enabled: this.draft.enabled,
      });

    request.subscribe({
      next: () => {
        this.saving.set(false);
        this.notice.set(
          isNew
            ? `L'app « ${this.draft.client_id} » peut désormais obtenir les jetons amont de ses utilisateurs.`
            : `Fiche « ${this.editing()} » mise à jour.`,
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

  /** Coupure immédiate sans perdre la fiche — l'inverse d'une révocation. */
  toggleEnabled(client: TrustedClient): void {
    this.error.set(null);
    this.api.updateTrustedClient(client.client_id, { enabled: !client.enabled }).subscribe({
      next: () => {
        this.notice.set(
          client.enabled
            ? `« ${client.client_id} » est suspendue : ses appels sont refusés dès maintenant.`
            : `« ${client.client_id} » est réactivée.`,
        );
        this.reload();
      },
      error: (err) => { this.error.set(this.formatApiError(err)); },
    });
  }

  revoke(client: TrustedClient): void {
    if (!confirm(
      `Révoquer « ${client.client_id} » ?\n\n`
      + "Cette app ne pourra plus obtenir de jeton amont, dès sa prochaine "
      + "requête. Les connexions des utilisateurs aux sites, elles, ne sont "
      + "pas touchées : elles restent utilisables par les autres apps.",
    )) return;

    this.api.deleteTrustedClient(client.client_id).subscribe({
      next: () => {
        this.notice.set(`« ${client.client_id} » n'est plus autorisée.`);
        this.reload();
      },
      error: (err) => { this.error.set(this.formatApiError(err)); },
    });
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
