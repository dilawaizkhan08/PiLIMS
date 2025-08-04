from rest_framework.permissions import BasePermission, SAFE_METHODS
from app import choices


class IsAdminOrSelf(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return request.user.is_authenticated
        if request.user.is_superuser:
            return True
        return obj == request.user

class IsSuperUser(BasePermission):

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)
    
class IsAdminUser(BasePermission):
    
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == choices.UserRole.ADMIN
    
