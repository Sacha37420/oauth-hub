import { Routes } from '@angular/router';
import { HomeComponent }    from './pages/home/home.component';
import { ProfileComponent } from './pages/profile/profile.component';
import { ProvidersComponent } from './pages/providers/providers.component';
import { TrustedClientsComponent } from './pages/trusted-clients/trusted-clients.component';

export const routes: Routes = [
  { path: '',        component: HomeComponent },
  { path: 'providers', component: ProvidersComponent },
  { path: 'trusted-clients', component: TrustedClientsComponent },
  { path: 'profile',   component: ProfileComponent },
  { path: '**',      redirectTo: '' },
];
