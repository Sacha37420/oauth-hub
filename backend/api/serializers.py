"""Sérialiseurs.

Règle non négociable de ce module : **aucun secret ne sort jamais d'ici**. Ni
le `client_secret` d'un site, ni le jeton amont d'un utilisateur. Le seul
endroit qui renvoie un jeton amont est `TokenView`, qui construit sa réponse à
la main précisément pour que ça reste un acte explicite et repérable.
"""
from rest_framework import serializers

from .models import Connection, Provider


class ProviderSerializer(serializers.ModelSerializer):
    """Un site OAuth. `client_secret` est en écriture seule.

    L'interface ne peut donc jamais réafficher un secret déposé — c'est voulu :
    un secret qu'on peut relire est un secret qui finit dans une capture
    d'écran. Pour savoir si le site est utilisable, on expose deux booléens
    dérivés plutôt que la valeur.
    """

    has_client_secret = serializers.BooleanField(read_only=True)
    # Déclaré explicitement pour DEUX raisons, sans lesquelles le cas le plus
    # courant est impossible à enregistrer :
    #   • `trim_whitespace=False` — DRF rogne les espaces par défaut, donc le
    #     séparateur " " (GitHub, GitLab, Google, et la valeur par défaut du
    #     formulaire) arrivait vide et était rejeté « This field may not be
    #     blank. » ;
    #   • `allow_blank=True` — pour accepter quand même une valeur vide, qui est
    #     normalisée en espace juste en dessous plutôt que refusée.
    scope_separator = serializers.CharField(
        max_length=4, required=False, allow_blank=True, trim_whitespace=False,
    )
    is_configured = serializers.BooleanField(read_only=True)
    client_secret = serializers.CharField(
        write_only=True, required=False, allow_blank=True,
        help_text=(
            "Laisser vide pour conserver le secret déjà enregistré. "
            "Toute valeur non vide remplace l'ancienne."
        ),
    )

    class Meta:
        model = Provider
        fields = [
            'slug', 'display_name', 'authorization_url', 'token_url',
            'client_id', 'client_secret', 'has_client_secret', 'is_configured',
            'default_scopes', 'scope_separator', 'use_pkce',
            'account_url', 'account_label_field',
            'enabled', 'notes', 'updated_at', 'updated_by',
        ]
        read_only_fields = ['updated_at', 'updated_by']

    def validate_scope_separator(self, value: str) -> str:
        # Un séparateur vide collerait les portées entre elles ('read:userrepo')
        # et produirait une demande d'autorisation silencieusement fausse.
        return value or ' '

    def _apply_secret(self, instance: Provider, raw_secret: str | None) -> None:
        # Absent OU vide ⇒ on ne touche pas au secret existant. Sans cette
        # règle, tout PATCH depuis un formulaire dont le champ secret est
        # (forcément) vide effacerait le secret et casserait la connexion de
        # tout le lab au premier « Enregistrer ».
        if raw_secret:
            instance.client_secret = raw_secret

    def create(self, validated_data):
        raw_secret = validated_data.pop('client_secret', '')
        provider = Provider(**validated_data)
        self._apply_secret(provider, raw_secret)
        provider.updated_by = self.context['request'].user.email
        provider.save()
        return provider

    def update(self, instance, validated_data):
        raw_secret = validated_data.pop('client_secret', None)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        self._apply_secret(instance, raw_secret)
        instance.updated_by = self.context['request'].user.email
        instance.save()
        return instance


class ConnectionSerializer(serializers.ModelSerializer):
    """Une connexion établie, **sans le jeton**."""

    provider = serializers.CharField(source='provider_id', read_only=True)
    provider_display_name = serializers.CharField(
        source='provider.display_name', read_only=True,
    )
    is_expired = serializers.BooleanField(read_only=True)
    has_refresh_token = serializers.SerializerMethodField()

    class Meta:
        model = Connection
        fields = [
            'provider', 'provider_display_name', 'scope', 'account_label',
            'expires_at', 'is_expired', 'has_refresh_token',
            'created_at', 'updated_at',
        ]

    def get_has_refresh_token(self, obj: Connection) -> bool:
        # Lu sur la colonne chiffrée : dire s'il EXISTE un refresh token ne
        # demande pas de le déchiffrer.
        return bool(obj.refresh_token_encrypted)
