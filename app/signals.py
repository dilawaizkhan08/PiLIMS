from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.utils import timezone
from app.models import Activity  # adjust path if needed
from threading import local

_user = local()  # thread-local user storage


def set_current_user(user):
    """Call this from middleware to store current user globally."""
    _user.value = user


def get_current_user():
    return getattr(_user, "value", None)


@receiver(post_save)
def log_create_update(sender, instance, created, **kwargs):
    """Logs create and update actions for all models."""
    # Avoid recursive or irrelevant models
    if sender.__name__ in ["Activity", "Session", "LogEntry", "Permission", "ContentType"]:
        return

    user = get_current_user()
    
    print(f"Signal received from {sender.__name__}, current user: {user}")
    action = "create" if created else "update"

    Activity.objects.create(
        user=user,
        model_name=sender.__name__,
        object_id=str(getattr(instance, "id", None)),
        action=action,
        description=f"{action.title()}d {sender.__name__}",
    )


@receiver(post_delete)
def log_delete(sender, instance, **kwargs):
    """Logs delete actions for all models."""
    if sender.__name__ in ["Activity", "Session", "LogEntry", "Permission", "ContentType"]:
        return

    user = get_current_user()
    Activity.objects.create(
        user=user,
        model_name=sender.__name__,
        object_id=str(getattr(instance, "id", None)),
        action="delete",
        description=f"Deleted {sender.__name__} with ID {getattr(instance, 'id', None)}",
    )



# app/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django_eventstream import send_event
from app.models import User, SampleForm, DynamicFormEntry, DynamicRequestEntry, Customer, Analysis, Inventory

MONITORED_MODELS = [
    "User",
    "SampleForm",
    "DynamicFormEntry",
    "DynamicRequestEntry",
    "Customer",
    "Analysis",
    "Inventory",
]


@receiver(post_save)
def broadcast_changes(sender, instance, created, **kwargs):
    model_name = sender.__name__

    if model_name not in MONITORED_MODELS:
        return

    data = {
        "model": model_name,
        "id": instance.id,
        "action": "created" if created else "updated",
    }

    try:
        # Make sure channel name matches what client subscribes to
        send_event("global", "message", data)
        print(f"✓ Event sent for {model_name}")
    except Exception as e:
        print(f"✗ EventStream error for {model_name}: {e}")