from django.urls import path
from rest_framework.routers import SimpleRouter

from .views import (
    AuthorizeView,
    CallbackView,
    MeView,
    MyConnectionDetailView,
    MyConnectionListView,
    ProviderStatusView,
    ProviderViewSet,
    TokenView,
    TrustedClientViewSet,
)

router = SimpleRouter()
router.register('providers', ProviderViewSet, basename='provider')
router.register('trusted-clients', TrustedClientViewSet, basename='trusted-client')

# Les routes explicites passent AVANT celles du routeur : `providers/<slug>/`
# du routeur est ancré en fin de chaîne et n'avalerait pas `…/token/`, mais
# l'ordre rend la lecture sûre sans avoir à raisonner sur les ancres.
urlpatterns = [
    path('me/', MeView.as_view()),

    # Utilisateur — ses propres connexions
    path('connections/', MyConnectionListView.as_view()),
    path('connections/<slug:slug>/', MyConnectionDetailView.as_view()),
    path('providers/<slug:slug>/authorize/', AuthorizeView.as_view()),

    # Retour du site externe — non authentifié par construction
    path('callback/<slug:slug>/', CallbackView.as_view()),

    # Apps tierces
    path('providers/<slug:slug>/token/', TokenView.as_view()),
    path('providers/<slug:slug>/status/', ProviderStatusView.as_view()),

    *router.urls,
]
