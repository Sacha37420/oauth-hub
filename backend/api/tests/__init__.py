"""Tests backend d'oauth-hub — `python manage.py test`.

Aucun réseau : le JWKS de Keycloak est remplacé par une clé locale et tout appel
au fournisseur externe est simulé (cf. base.py). Les réglages sensibles sont
surchargés : rien ici ne dépend du contenu du `.env`.
"""
