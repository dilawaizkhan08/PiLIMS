from django.db import models

class UserRole(models.TextChoices):
    ADMIN = "Admin", "Admin"
    USER = "User", "User"
