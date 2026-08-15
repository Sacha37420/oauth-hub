import { Component, inject, OnInit, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';

import { ApiService, Connection, Me } from '../../core/api.service';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [DatePipe, RouterLink],
  templateUrl: './profile.component.html',
  styleUrl: './profile.component.scss',
})
export class ProfileComponent implements OnInit {
  private api = inject(ApiService);

  me = signal<Me | null>(null);
  connections = signal<Connection[]>([]);
  loading = signal(true);
  error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.getMe().subscribe({
      next: (data) => {
        this.me.set(data);
        this.loading.set(false);
        this.api.listConnections().subscribe({
          next: (conns) => this.connections.set(conns),
        });
      },
      error: (err) => {
        this.loading.set(false);
        this.error.set(`Impossible de charger le profil (${err.status ?? 'réseau'})`);
      },
    });
  }
}
