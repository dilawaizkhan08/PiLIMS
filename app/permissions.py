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
    


from rest_framework.permissions import BasePermission
from app import models


class HasModulePermission(BasePermission):

    STATUS_PERMISSION_MAP = {
        "received": "receive",
        "in_progress": "result_entry",
        "completed": "result_entry",
        "release": "release",
        "rejected": "release",
        "hold": "cancel_restore",
        "unhold": "cancel_restore",
        "reactivate": "reactivate",
        "assign_analyst": "result_entry",
    }

    def has_permission(self, request, view):

        user = request.user

        if not user.is_authenticated:
            return False

        # Superuser bypass
        if user.is_superuser:
            return True

        # 🔹 1. Get Role ID from Header
        role_id = request.headers.get("X-ROLE-ID")

        if not role_id:
            return False  # Role must be provided

        try:
            role = user.roles.get(id=role_id)
        except models.Role.DoesNotExist:
            return False  # User does not have this role

        # 🔹 2. Detect model (module name)
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
            return True

        module_name = model._meta.db_table

        # 🔹 3. Map DRF action to CRUD
        action_map = {
            "create": "create",
            "list": "view",
            "retrieve": "view",
            "update": "update",
            "partial_update": "update",
            "destroy": "delete",
            "update_status": "update",
            "stats": "view",
        }

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

        action = action_map.get(action, action)

        if not action:
            return False

        # 🔹 4. Check CRUD permission
        if role.permissions.filter(module=module_name, action=action).exists():
            return True

        # 🔹 5. Special Status Handling
        if action == "update" and request.method == "POST":
            status_to_set = request.data.get("status")

            if status_to_set:
                required_perm = self.STATUS_PERMISSION_MAP.get(status_to_set)

                if required_perm:
                    return role.permissions.filter(
                        module=module_name,
                        action=required_perm
                    ).exists()

        return False
