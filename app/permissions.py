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
    Works for both APIView and ViewSet.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False

        # 1. Identify model
        model = None
        if hasattr(view, "queryset") and view.queryset is not None:
            model = view.queryset.model
        elif hasattr(view, "get_queryset"):
            try:
                model = view.get_queryset().model
            except Exception:
                pass
        elif hasattr(view, "serializer_class") and hasattr(view.serializer_class.Meta, "model"):
            model = view.serializer_class.Meta.model

        if not model:
            return True  # fallback: allow if no model is attached

        module_name = model._meta.db_table

        # 2. Map DRF actions → CRUD
        action_map = {
            "create": "create",
            "list": "view",
            "retrieve": "view",
            "update": "update",
            "partial_update": "update",
            "destroy": "delete",
        }

        # For APIView (no .action attribute)
        action = getattr(view, "action", None)
        if action is None:
            if request.method == "GET":
                action = "view"
            elif request.method == "POST":
                action = "create"
            elif request.method in ["PUT", "PATCH"]:
                action = "update"
            elif request.method == "DELETE":
                action = "delete"

        action = action_map.get(action)
        if not action:
            return False

        # 3. Check user roles and permissions
        for role in user.roles.all():
            if role.permissions.filter(module=module_name, action=action).exists():
                return True

        return False


