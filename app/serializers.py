from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework.authtoken.models import Token
from app import models
from django.core.exceptions import ValidationError as DjangoValidationError
from app import choices
from django.contrib.auth import password_validation
from rest_framework.exceptions import ValidationError


ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif']  # Allowed MIME types
MAX_SIZE = 5 * 1024 * 1024


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    role = serializers.ChoiceField(choices=choices.UserRole.choices, default=choices.UserRole.USER)

    class Meta:
        model = get_user_model()
        fields = ['email', 'password', 'name', 'role']

    def create(self, validated_data):
        password = validated_data.pop('password')
        validated_data.pop('username', None)  # Avoid username conflicts if using AbstractUser

        user = get_user_model()(**validated_data)
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        if not data.get("email") or not data.get("password"):
            raise serializers.ValidationError("Email and password are required.")
        return data


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    last_login = serializers.DateTimeField(read_only=True)

    class Meta:
        model = models.User
        fields = [
            'id', 'email', 'password', 'name', 'role','phone_number', 'is_active',
            'created_at', 'updated_at', 'is_deleted', 'last_login', 'profile_picture'
        ]

    def create(self, validated_data):
        request = self.context.get('request')
        password = validated_data.pop('password')
        validated_data.pop('username', None)

        user = models.User(**validated_data)
        user.set_password(password)

        if request and hasattr(request, "user") and request.user.is_authenticated:
            user.created_by = request.user

        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance

class UserProfileSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(write_only=True, required=False)
    new_password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = get_user_model()
        fields = [
            "email", "name", "profile_picture", 'phone_number',
            "old_password", "new_password", "confirm_password"
        ]
        read_only_fields = ["email"]

    def validate(self, data):
        old_password = data.get("old_password")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if new_password or confirm_password or old_password:
            if not old_password:
                raise ValidationError({"old_password": "Old password is required to set a new password."})
            if not new_password or not confirm_password:
                raise ValidationError({"new_password": "New password and confirmation are required."})
            if new_password != confirm_password:
                raise ValidationError({"confirm_password": "Passwords do not match."})

            user = self.instance
            if not user.check_password(old_password):
                raise ValidationError({"old_password": "Old password is incorrect."})

            password_validation.validate_password(new_password, user=user)

        return data

    def update(self, instance, validated_data):
        old_password = validated_data.pop("old_password", None)
        new_password = validated_data.pop("new_password", None)
        validated_data.pop("confirm_password", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if old_password and new_password:
            instance.set_password(new_password)

        instance.save()
        return instance

    def validate_profile_picture(self, value):
        if value:
            if value.content_type not in ALLOWED_IMAGE_TYPES:
                raise ValidationError("Invalid file type. Only JPEG, PNG, or GIF images are allowed.")
            if value.size > MAX_SIZE:
                raise ValidationError("The file size is too large. Maximum allowed size is 5 MB.")
        return value

    def to_representation(self, instance):
        request = self.context.get("request")
        return {
            "id": instance.id,
            "email": instance.email,
            "name": instance.name,
            "role": instance.role,
            "phone_number": instance.phone_number, 
            "is_active": instance.is_active,
            "created_at": instance.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": instance.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
            "is_deleted": instance.is_deleted,
            "last_login": instance.last_login.strftime("%Y-%m-%d %H:%M:%S") if instance.last_login else None,
            "profile_picture": request.build_absolute_uri(instance.profile_picture.url) if instance.profile_picture and request else None
        }


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not models.User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user is associated with this email.")
        return value
    

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)

