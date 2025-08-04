from django.core.management.base import BaseCommand
from app.models import User  # replace with your app

class Command(BaseCommand):
    help = 'Create a default superuser'

    def handle(self, *args, **kwargs):
        email = "superadmin@example.com"
        username = 'superadmin@example.com'
        password = "aszx1234"
        name = "Super Admin"

        if not User.objects.filter(email=email).exists():
            User.objects.create_superuser(
                email=email,
                password=password,
                name=name,
                username=username,
                is_active=True,
                is_staff=True,
                is_superuser=True
            )
            self.stdout.write(self.style.SUCCESS("Superuser created successfully."))
        else:
            self.stdout.write(self.style.WARNING("Superuser already exists."))
