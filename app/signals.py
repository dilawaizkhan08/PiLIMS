from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from app.models import Activity
from threading import local

_user = local()
_old_data = local()

def set_current_user(user):
    _user.value = user

def get_current_user():
    return getattr(_user, "value", None)

def model_to_dict(instance):
    """Serialize model instance into dict suitable for JSONField."""
    data = {}
    for field in instance._meta.fields:
        value = getattr(instance, field.name)

        # Convert datetime/date to ISO format
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        # Optional: convert UUID to str
        if hasattr(value, "hex"):
            value = str(value)

        data[field.name] = value
    return data


IGNORED = ["Activity", "Session", "LogEntry", "Permission", "ContentType"]
    

# -----------------------------
# STORE OLD DATA BEFORE UPDATE
# -----------------------------
@receiver(pre_save)
def store_old_data(sender, instance, **kwargs):
    if sender.__name__ in IGNORED:
        return

    if instance.pk:
        try:
            old = sender.objects.get(pk=instance.pk)
            _old_data.value = model_to_dict(old)
        except sender.DoesNotExist:
            _old_data.value = None
    else:
        _old_data.value = None


# -----------------------------
# CREATE + UPDATE LOGGING
# -----------------------------
@receiver(post_save)
def log_create_update(sender, instance, created, **kwargs):
    try:
        if sender.__name__ in IGNORED:
            return

        user = get_current_user()
        old = getattr(_old_data, "value", None)
        new = model_to_dict(instance)

        if created:
            changes = {"old": None, "new": new}
            action = "create"
            desc = f"Created {sender.__name__}"
        else:
            changed_fields = {}
            if old:
                for field, value in new.items():
                    if old.get(field) != value:
                        changed_fields[field] = value

            changes = {"old": old, "new": changed_fields}
            action = "update"
            desc = f"Updated {sender.__name__}"

        Activity.objects.create(
            user=user,
            model_name=sender.__name__,
            object_id=str(getattr(instance, "id", None)),
            action=action,
            description=desc,
            changes=changes
        )
    except Exception as e:
        print(f"[Activity Signal Error] {sender.__name__}: {e}")


# -----------------------------
# DELETE LOGGING
# -----------------------------
@receiver(post_delete)
def log_delete(sender, instance, **kwargs):
    try:
        if sender.__name__ in IGNORED:
            return

        user = get_current_user()
        old = model_to_dict(instance)

        Activity.objects.create(
            user=user,
            model_name=sender.__name__,
            object_id=str(getattr(instance, "id", None)),
            action="delete",
            description=f"Deleted {sender.__name__}",
            changes={"old": old, "new": None}
        )
    except Exception as e:
        print(f"[Activity Delete Signal Error] {sender.__name__}: {e}")
