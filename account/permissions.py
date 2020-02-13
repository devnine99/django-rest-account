from django.contrib.auth import get_user_model
from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsOwnerOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'user'):
            return obj.user.id == request.user.id
        elif obj.__class__ == get_user_model():
            return obj.id == request.user.id
        return False


class IsOwnerOrReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        elif hasattr(obj, 'user'):
            return obj.user.id == request.user.id
        return False
