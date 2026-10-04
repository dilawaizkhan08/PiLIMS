from django.core.management.base import BaseCommand
from app.models import User, Role, Permission


class Command(BaseCommand):
    help = "Create or update OQ team user with OQ role and dynamic form entry create permission"

    def handle(self, *args, **options):

        # =========================
        # Create / Get OQ Role
        # =========================
        role, role_created = Role.objects.get_or_create(
            name="OQ"
        )

        # Remove existing permissions from OQ role
        # so OQ has ONLY the required permission
        role.permissions.all().delete()

        # Add only required permission
        Permission.objects.create(
            role=role,
            module="app_dynamicformentry",
            action="create",
        )

        # =========================
        # Create / Update OQ Team User
        # =========================
        user, user_created = User.objects.get_or_create(
            name="OQ team",
            defaults={
                "username": None,
                "email": None,
                "is_active": True,
                "is_staff": False,
                "is_2fa_enabled": False,
            },
        )

        user.username = None
        user.email = None
        user.set_password("QA#12345")
        user.is_active = True
        user.is_staff = False
        user.is_2fa_enabled = False
        user.save()

        # =========================
        # Assign OQ Role to User
        # =========================
        user.roles.add(role)

        # =========================
        # Output
        # =========================
        if user_created:
            self.stdout.write(
                self.style.SUCCESS(
                    "OQ team user created successfully."
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "OQ team user updated successfully."
                )
            )

        if role_created:
            self.stdout.write(
                self.style.SUCCESS(
                    "OQ role created successfully."
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "OQ role updated successfully."
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                "Permission assigned: app_dynamicformentry -> create"
            )
        )

        self.stdout.write(
            self.style.SUCCESS(
                "OQ role assigned to OQ team user."
            )
        )