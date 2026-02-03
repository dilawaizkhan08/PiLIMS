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
    Check if user has required CRUD permission on a given module (DB table)
    or permission to perform a specific status update.
    Works for both APIView and ViewSet.
    """

    # Map dynamic statuses → permission actions
    STATUS_PERMISSION_MAP = {
        "received": "receive",
        "in_progress": "result_entry",
        "completed": "result_entry",
        "authorized": "authorize",
        "rejected": "authorize",
        "hold": "cancel_restore",
        "unhold": "cancel_restore",
        "reactivate": "reactivate",
        "assign_analyst": "result_entry",
    }

    def has_permission(self, request, view):
        user = request.user
        if not user.is_authenticated:
            return False

        if user.is_superuser:
            return True

        # 1️⃣ Identify model
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

        # 2️⃣ Map DRF actions → CRUD
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

        # Handle custom GET endpoints like /stats/
        if action and action.startswith("get_"):
            action = "view"

        # For APIView (no .action)
        if action is None:
            if request.method == "GET":
                action = "view"
            elif request.method == "POST":
                action = "create"
            elif request.method in ["PUT", "PATCH"]:
                action = "update"
            elif request.method == "DELETE":
                action = "delete"

        # Map action to CRUD fallback
        action = action_map.get(action, action)

        if not action:
            return False

        # 3️⃣ Check user roles and permissions for CRUD
        for role in user.roles.all():
            if role.permissions.filter(module=module_name, action=action).exists():
                return True

        # 4️⃣ Special handling: check dynamic status permissions
        # Example: in DynamicSampleFormEntryViewSet, update_status action
        if hasattr(view, "request") and action == "update" and request.method == "POST":
            status_to_set = request.data.get("status")
            if status_to_set:
                required_perm = self.STATUS_PERMISSION_MAP.get(status_to_set)
                if required_perm:
                    for role in user.roles.all():
                        if role.permissions.filter(module=module_name, action=required_perm).exists():
                            return True
                    # Deny if user lacks permission for this status
                    return False

        # 5️⃣ Deny by default
        return False

