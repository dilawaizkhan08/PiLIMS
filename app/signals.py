from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
from app.models import Activity, BaseModel
from threading import local

_user = local()

def set_current_user(user):
    _user.value = user

def get_current_user():
    return getattr(_user, "value", None)

@receiver(post_save)
def create_or_update_activity(sender, instance, created, **kwargs):
    try:
        if not issubclass(sender, BaseModel):
            return

        if sender == Activity:
            return

        if sender.__name__ == "User":
            request_user = get_current_user()
            if not request_user or request_user != instance:
                return

        user = get_current_user()

        Activity.objects.create(
            user_id=user.id if user else None,  # <-- id directly
            model_name=sender.__name__,
            object_id=str(instance.pk),
            action="create" if created else "update",
            description=f"{sender.__name__} {'created' if created else 'updated'} at {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        )

    except Exception as e:
        print(f"[ActivityLogError] {e}")


@receiver(post_delete)
def delete_activity(sender, instance, **kwargs):
    try:
        if not issubclass(sender, BaseModel):
            return
        if sender == Activity:
            return
        if sender.__name__ == "User":
            return

        user = get_current_user()

        Activity.objects.create(
            user_id=user.id if user else None,  # <-- id directly
            model_name=sender.__name__,
            object_id=str(instance.pk),
            action="delete",
            description=f"{sender.__name__} deleted at {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        )
    except Exception as e:
        print(f"[ActivityDeleteLogError] {e}")
