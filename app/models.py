from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext as _
from django.db import models
from django.conf import settings
import uuid
from app import choices
from django.utils import timezone


class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        abstract = True
        ordering = ["-id"]


class User(AbstractUser, BaseModel):
    username = models.CharField(max_length=150, null=True, blank=True)
    email = models.EmailField(_("Email"), unique=True, null=False)
    role = models.CharField(max_length=20,choices=choices.UserRole.choices,default=choices.UserRole.USER,)
    profile_picture = models.ImageField(upload_to="profile_pictures/", null=True, blank=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    created_by = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='created_users')
    last_login = models.DateTimeField(blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)


    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    def __str__(self):
        return self.email

