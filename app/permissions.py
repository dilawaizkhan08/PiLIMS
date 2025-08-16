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
    


class HasModulePermission(BasePermission):
    """
    Check if user has required CRUD permission on a given module (DB table).
    """

    def has_permission(self, request, view):
        # 1. Identify module (DB table) from view
        model = getattr(view, 'queryset', None)
        if model is None:
            return False
        
        module_name = model.model._meta.db_table  # e.g. app_unit

        # 2. Map DRF actions to our PERMISSION_CHOICES
        action_map = {
            "create": "create",
            "list": "view",
            "retrieve": "view",
            "update": "update",
            "partial_update": "update",
            "destroy": "delete",
        }

        action = action_map.get(view.action)
        if action is None:
            return False

        # 3. Get all roles of user and check permissions
        user = request.user
        if not user.is_authenticated:
            return False

        for role in user.roles.all():
            if role.permissions.filter(module=module_name, action=action).exists():
                return True

        return False
    
