from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework.authtoken.models import Token
from app import models
from app import choices
from django.contrib.auth import password_validation
from rest_framework.exceptions import ValidationError
import ast
import inflection
from django.core.files.uploadedfile import UploadedFile
from django.contrib.auth.password_validation import validate_password as dj_validate_password
import re
from django.utils import timezone
import phonenumbers
from django.apps import apps
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import json
from .choices import ComponentTypes

def get_config(key, default=None):
    from .models import SystemConfiguration
    config = SystemConfiguration.objects.filter(key=key).first()
    return config.value if config else default


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
        fields = '__all__'
        read_only_fields = ["groups", "user_permissions"]

    def create(self, validated_data):
        request = self.context.get('request')

        # Remove fields not allowed in **kwargs
        validated_data.pop("groups", None)
        validated_data.pop("user_permissions", None)

        password = validated_data.pop("password")

        user = models.User(**validated_data)
        user.set_password(password)

        if request and hasattr(request, "user") and request.user.is_authenticated:
            user.created_by = request.user

        user.save()
        return user

    def update(self, instance, validated_data):
        validated_data.pop("groups", None)
        validated_data.pop("user_permissions", None)

        password = validated_data.pop('password', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()
        return instance

    # ---------------- VALIDATIONS ----------------

    def validate_username(self, value):
        user_id = self.instance.id if self.instance else None
        if models.User.objects.filter(username=value).exclude(id=user_id).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def validate_name(self, value):
        max_length = int(get_config("max_name_length", 70))
        if len(value) > max_length:
            raise serializers.ValidationError(
                f"Name cannot exceed {max_length} characters."
            )
        return value

    def validate_password(self, value):
        min_length = int(get_config("min_password_length", 10))
        if len(value) < min_length:
            raise serializers.ValidationError(
                f"Password must be at least {min_length} characters long."
            )

        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r"[0-9]", value):
            raise serializers.ValidationError("Password must contain at least one number.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", value):
            raise serializers.ValidationError("Password must contain at least one special character.")

        try:
            dj_validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)

        return value

    def validate_dob(self, value):
        if value and value > timezone.now().date():
            raise serializers.ValidationError("Date of Birth cannot be in the future.")
        return value

    def validate_phone_number(self, value):
        if value:
            try:
                parsed = phonenumbers.parse(value, None)
                if not phonenumbers.is_valid_number(parsed):
                    raise serializers.ValidationError("Enter a valid international phone number.")
            except phonenumbers.NumberParseException:
                raise serializers.ValidationError("Invalid phone number format.")
        return value



class UserProfileSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(write_only=True, required=False)
    new_password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = get_user_model()
        exclude = ["password"]
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

            # ✅ Dynamic password length check
            min_length = int(get_config("min_password_length", 8))
            if len(new_password) < min_length:
                raise ValidationError({"new_password": f"Password must be at least {min_length} characters long."})

            # ✅ Django’s default password validators
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

    def validate_name(self, value):
        max_length = int(get_config("max_name_length", 70))
        if len(value) > max_length:
            raise serializers.ValidationError(f"Name cannot exceed {max_length} characters (limit: {max_length}).")
        return value

    def validate_profile_picture(self, value):
        if value:
            if value.content_type not in ALLOWED_IMAGE_TYPES:
                raise ValidationError("Invalid file type. Only JPEG, PNG, or GIF images are allowed.")
            if value.size > MAX_SIZE:
                raise ValidationError("The file size is too large. Maximum allowed size is 5 MB.")
        return value


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not models.User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user is associated with this email.")
        return value
    

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)


class UserGroupSerializer(serializers.ModelSerializer):
    users = serializers.PrimaryKeyRelatedField(
        queryset=models.User.objects.all(), 
        many=True
    )
    # read-only field for user names
    names = serializers.SerializerMethodField()

    class Meta:
        model = models.UserGroup
        fields = ['id', 'name', 'users', 'names']

    def get_names(self, obj):
        return [user.name for user in obj.users.all()]


class CustomFunctionSerializer(serializers.ModelSerializer):
    # Force variables to be a list of strings
    variables = serializers.ListField(
        child=serializers.CharField(), allow_empty=False
    )

    class Meta:
        model = models.CustomFunction
        fields = ['id', 'name', 'variables', 'script']

    def validate(self, data):
        variables = data.get("variables", [])
        script = data.get("script", "")

        # 1. Syntax check
        try:
            tree = ast.parse(script)
        except SyntaxError as e:
            raise serializers.ValidationError(
                {"script": f"Invalid Python script: {e}"}
            )

        # 2. Collect variables actually used
        used_vars = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }

        # Allow "result" as output
        allowed_vars = set(variables + ["result"])

        # 3. Find extra vars not in the list
        extra_vars = used_vars - allowed_vars
        if extra_vars:
            raise serializers.ValidationError(
                {"script": f"Invalid variable(s) used: {', '.join(extra_vars)}"}
            )

        return data


class TestMethodSerializer(serializers.ModelSerializer):
    user_groups = UserGroupSerializer(many=True, read_only=True)
    user_groups_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all(), write_only=True, required=False
    )

    class Meta:
        model = models.TestMethod
        fields = ['id', 'name', 'description', 'user_groups', 'user_groups_ids']

    def create(self, validated_data):
        user_groups = validated_data.pop('user_groups_ids', [])
        test_method = super().create(validated_data)
        test_method.user_groups.set(user_groups)  # set M2M relationship
        return test_method

    def update(self, instance, validated_data):
        user_groups = validated_data.pop('user_groups_ids', None)
        instance = super().update(instance, validated_data)
        if user_groups is not None:
            instance.user_groups.set(user_groups)
        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['user_groups_ids'] = list(instance.user_groups.values_list('id', flat=True))
        return data


class ParameterMappingSerializer(serializers.Serializer):
    parameter = serializers.CharField()
    component = serializers.IntegerField()



class ComponentSerializer(serializers.ModelSerializer):

    unit_id = serializers.PrimaryKeyRelatedField(
        queryset=models.Unit.objects.all(),
        source="unit",
        required=False
    )
    unit = serializers.StringRelatedField(read_only=True)

    list_id = serializers.PrimaryKeyRelatedField(
        queryset=models.List.objects.all(),
        source="listname",
        write_only=True,
        required=False
    )
    listname = serializers.StringRelatedField(read_only=True)

    function_id = serializers.PrimaryKeyRelatedField(
        queryset=models.CustomFunction.objects.all(),
        source="custom_function",
        write_only=True,
        required=False
    )
    function = CustomFunctionSerializer(source="custom_function", read_only=True)

    spec_limits = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )

    rounding_display = serializers.CharField(source='get_rounding_display', read_only=True)
    parameters = ParameterMappingSerializer(many=True, required=False)

    class Meta:
        model = models.Component
        fields = [
            'id', 'analysis', 'name', 'type',
            'unit_id', 'unit',
            'spec_limits', 'description',
            'optional', 'calculated',
            'function_id', 'function',
            'minimum', 'maximum', 'rounding', 'rounding_display',
            'decimal_places', 'list_id', 'listname', 'parameters'
        ]

    def validate(self, attrs):
        comp_type = attrs.get("type") or getattr(self.instance, "type", None)

        if comp_type == choices.ComponentTypes.LIST:
            list_obj = attrs.get("listname") or getattr(self.instance, "listname", None)
            if not list_obj:
                raise serializers.ValidationError(
                    {"list_id": "List is required when type is 'List'."}
                )

            allowed_values = set(list_obj.values.values_list("value", flat=True))
            spec_limits = attrs.get("spec_limits")

            if not spec_limits:
                attrs["spec_limits"] = list(allowed_values)
            else:
                invalid = [val for val in spec_limits if val not in allowed_values]
                if invalid:
                    raise serializers.ValidationError({
                        "spec_limits": f"Invalid values for list '{list_obj.name}': {', '.join(invalid)}"
                    })

        return attrs

    def create(self, validated_data):
        parameters_data = validated_data.pop("parameters", [])
        # ⚠️ ab analysis context se nahi aayega, directly null allow hoga
        component = models.Component.objects.create(**validated_data)

        if component.calculated and component.custom_function:
            expected_vars = set(component.custom_function.variables)
            provided_vars = {p["parameter"] for p in parameters_data}

            missing = expected_vars - provided_vars
            if missing:
                raise serializers.ValidationError(
                    {"parameters": f"Missing mappings for variables: {', '.join(missing)}"}
                )

            extra = provided_vars - expected_vars
            if extra:
                raise serializers.ValidationError(
                    {"parameters": f"Unexpected variables: {', '.join(extra)}"}
                )

            for param in parameters_data:
                var_name = param["parameter"]
                comp_id = param["component"]

                try:
                    mapped_component = models.Component.objects.get(id=comp_id)
                except models.Component.DoesNotExist:
                    raise serializers.ValidationError(
                        {"parameters": f"Component {comp_id} not found"}
                    )

                models.ComponentFunctionParameter.objects.create(
                    component=component,
                    parameter=var_name,
                    mapped_component=mapped_component
                )

        return component

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.calculated and instance.custom_function:
            data["parameters"] = [
                {
                    "parameter": p.parameter,
                    "component": {
                        "id": p.mapped_component.id,
                        "name": p.mapped_component.name,
                    }
                }
                for p in instance.function_parameters.all()
            ]
        return data


class AnalysisAttachmentSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = models.AnalysisAttachment
        fields = ['id', 'file', 'url']

    def get_url(self, obj):
        request = self.context.get("request")
        if obj.file and request:
            return request.build_absolute_uri(obj.file.url)
        return None



class AnalysisSerializer(serializers.ModelSerializer):
    attachments = AnalysisAttachmentSerializer(many=True, read_only=True)
    attachment_urls = serializers.ListField(
        child=serializers.URLField(),
        write_only=True,
        required=False
    )

    component_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False
    )
    components = ComponentSerializer(many=True, read_only=True)

    user_groups_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=models.UserGroup.objects.all(),
        write_only=True,
        source="user_groups",
        required=False
    )
    user_groups = UserGroupSerializer(many=True, read_only=True)

    test_method_id = serializers.PrimaryKeyRelatedField(
        queryset=models.TestMethod.objects.all(),
        source="test_method",
        write_only=True
    )
    test_method = TestMethodSerializer(read_only=True)

    class Meta:
        model = models.Analysis
        fields = [
            "id",
            "name",
            "version",
            "alias_name",
            "user_groups",
            "user_groups_ids",
            "type",
            "test_method",
            "test_method_id",
            "price",
            "description",
            "attachments",
            "attachment_urls",
            "components",
            "component_ids",   
        ]

    def create(self, validated_data):
        attachment_urls = validated_data.pop("attachment_urls", [])
        user_groups = validated_data.pop("user_groups", [])
        component_ids = validated_data.pop("component_ids", [])

        analysis = models.Analysis.objects.create(**validated_data)
        analysis.user_groups.set(user_groups)

        # Attach attachments
        for url in attachment_urls:
            file_path = url.split('/media/')[-1]
            try:
                attachment = models.AnalysisAttachment.objects.get(file=file_path)
            except models.AnalysisAttachment.DoesNotExist:
                raise serializers.ValidationError(
                    {"attachment_urls": f"Attachment not found for URL: {url}"}
                )
            attachment.analysis = analysis
            attachment.save()

        # Attach components
        if component_ids:
            components = models.Component.objects.filter(id__in=component_ids)
            for comp in components:
                comp.analysis = analysis
                comp.save()

        return analysis

    def update(self, instance, validated_data):
        attachment_urls = validated_data.pop("attachment_urls", [])
        user_groups = validated_data.pop("user_groups", [])
        component_ids = validated_data.pop("component_ids", [])

        # Update fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update user groups
        if user_groups:
            instance.user_groups.set(user_groups)

        # Update attachments
        if attachment_urls:
            # Optional: clear old attachments if desired
            # instance.attachments.all().delete()
            for url in attachment_urls:
                file_path = url.split('/media/')[-1]
                try:
                    attachment = models.AnalysisAttachment.objects.get(file=file_path)
                except models.AnalysisAttachment.DoesNotExist:
                    raise serializers.ValidationError(
                        {"attachment_urls": f"Attachment not found for URL: {url}"}
                    )
                attachment.analysis = instance
                attachment.save()

        # Update components
        if component_ids:
            # Clear old components
            instance.components.clear()  # if using ManyToMany
            components = models.Component.objects.filter(id__in=component_ids)
            for comp in components:
                comp.analysis = instance
                comp.save()

        return instance



class InstrumentHistorySerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)  # Allow PATCH with ID

    class Meta:
        model = models.InstrumentHistory
        fields = [
            'id', 'created_at', 'updated_at', 'is_deleted',
            'action_type', 'start_date', 'instrument'
        ]
        extra_kwargs = {
            'instrument': {'required': False}
        }


class NullableDateField(serializers.DateField):
    def to_internal_value(self, value):
        if value in ("", None, "null"):   # handle empty, real null, and string "null"
            return None
        return super().to_internal_value(value)


class InstrumentSerializer(serializers.ModelSerializer):
    history = InstrumentHistorySerializer(many=True, required=False)

    # ✅ Date fields should allow null
    next_calibration_date = NullableDateField(required=False, allow_null=True)
    next_prevention_date = NullableDateField(required=False, allow_null=True)

    # ✅ Nested serializer for GET
    user_groups = UserGroupSerializer(many=True, read_only=True)

    # ✅ Accept IDs for write
    user_groups_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all(), required=False
    )

    class Meta:
        model = models.Instrument
        fields = [
            'id', 'created_at', 'updated_at', 'is_deleted',
            'name', 'vendor', 'manufacturer', 'serial_no', 'model_no',
            'description', 'calibration_period', 'next_calibration_date',
            'prevention_period', 'next_prevention_date',
            'user_groups',
            'user_groups_ids',
            'history'
        ]


    def to_representation(self, instance):
        """Add user_groups_ids to GET response"""
        data = super().to_representation(instance)
        data['user_groups_ids'] = list(instance.user_groups.values_list('id', flat=True))
        return data

    def create(self, validated_data):
        history_data = validated_data.pop('history', [])
        user_groups = validated_data.pop('user_groups_ids', [])

        instrument = models.Instrument.objects.create(**validated_data)
        instrument.user_groups.set(user_groups)

        for hist in history_data:
            models.InstrumentHistory.objects.create(instrument=instrument, **hist)

        return instrument

    def update(self, instance, validated_data):
        history_data = validated_data.pop('history', None)
        user_groups = validated_data.pop('user_groups_ids', None)

        # Update instrument fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # ✅ Update M2M if provided
        if user_groups is not None:
            instance.user_groups.set(user_groups)

        # Update or create history entries
        if history_data is not None:
            existing_ids = {h.id: h for h in instance.history.all()}
            sent_ids = []

            for hist_data in history_data:
                hist_id = hist_data.pop('id', None)

                if hist_id and hist_id in existing_ids:
                    hist_obj = existing_ids[hist_id]
                    for attr, val in hist_data.items():
                        setattr(hist_obj, attr, val)
                    hist_obj.save()
                    sent_ids.append(hist_id)
                else:
                    new_hist = models.InstrumentHistory.objects.create(
                        instrument=instance, **hist_data
                    )
                    sent_ids.append(new_hist.id)

            # Optional: delete records not sent
            for hist_id, hist_obj in existing_ids.items():
                if hist_id not in sent_ids:
                    hist_obj.delete()

        return instance


class StockSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)  # Allow PATCH with ID

    class Meta:
        model = models.Stock
        fields = [
            'id', 'inventory', 'stock_date', 'expiration_date', 'notes', 'quantity'
        ]
        extra_kwargs = {
            'inventory': {'required': False}
        }


class InventorySerializer(serializers.ModelSerializer):
    stocks = StockSerializer(many=True)
    user_groups = UserGroupSerializer(many=True, read_only=True)
    user_groups_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all(), required=False
    )
    unit_name = serializers.SerializerMethodField()

    class Meta:
        model = models.Inventory
        fields = [
            'id', 'name', 'type',
            'user_groups',        # ✅ GET → [{id, name}]
            'user_groups_ids',    # ✅ POST/PUT → [1,2]
            'location', 'unit', 'unit_name', 'total_quantity',
            'description', 'stocks'
        ]

    def get_unit_name(self, obj):
        return obj.unit.name if obj.unit else None

    def create(self, validated_data):
        stocks_data = validated_data.pop('stocks', [])
        user_groups = validated_data.pop('user_groups_ids', [])

        inventory = models.Inventory.objects.create(**validated_data)
        inventory.user_groups.set(user_groups)

        for stock_data in stocks_data:
            models.Stock.objects.create(inventory=inventory, **stock_data)

        return inventory

    def update(self, instance, validated_data):
        stocks_data = validated_data.pop('stocks', None)
        user_groups = validated_data.pop('user_groups_ids', None)

        # Update inventory fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # ✅ Update M2M if provided
        if user_groups is not None:
            instance.user_groups.set(user_groups)

        # ✅ Update or create stock entries
        if stocks_data is not None:
            existing_ids = {s.id: s for s in instance.stocks.all()}
            sent_ids = []

            for stock_data in stocks_data:
                stock_id = stock_data.pop('id', None)

                if stock_id and stock_id in existing_ids:
                    stock_obj = existing_ids[stock_id]
                    for attr, val in stock_data.items():
                        setattr(stock_obj, attr, val)
                    stock_obj.save()
                    sent_ids.append(stock_id)
                else:
                    new_stock = models.Stock.objects.create(
                        inventory=instance, **stock_data
                    )
                    sent_ids.append(new_stock.id)

            # Optional: delete records not sent
            for stock_id, stock_obj in existing_ids.items():
                if stock_id not in sent_ids:
                    stock_obj.delete()

        return instance
    

    def to_representation(self, instance):
        """Add user_groups_ids to GET response"""
        data = super().to_representation(instance)
        data['user_groups_ids'] = list(instance.user_groups.values_list('id', flat=True))
        return data


class UnitSerializer(serializers.ModelSerializer):
    # Show user group names in response
    user_group_names = serializers.SerializerMethodField(read_only=True)

    # Accept multiple IDs for assignment
    user_groups = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all()
    )

    class Meta:
        model = models.Unit
        fields = [
            'id', 'name', 'symbol',
            'user_groups',        # ✅ M2M IDs
            'user_group_names',   # ✅ readable names
            'description', 'created_at', 'updated_at'
        ]

    def get_user_group_names(self, obj):
        return [ug.name for ug in obj.user_groups.all()]

    def create(self, validated_data):
        # Extract and remove M2M field
        user_groups = validated_data.pop("user_groups", [])
        # Create instance without M2M
        unit = models.Unit.objects.create(**validated_data)
        # Assign M2M
        unit.user_groups.set(user_groups)
        return unit

    def update(self, instance, validated_data):
        # Handle M2M only if present
        user_groups = validated_data.pop("user_groups", None)

        # Update normal fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update M2M (set only if provided, supports PATCH)
        if user_groups is not None:
            instance.user_groups.set(user_groups)
        return instance


class ValueSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)

    class Meta:
        model = models.Value
        fields = ['id', 'value']


class ListSerializer(serializers.ModelSerializer):
    values = ValueSerializer(many=True)

    # ✅ Nested serializer for GET
    user_groups = UserGroupSerializer(many=True, read_only=True)

    # ✅ Accept IDs for write
    user_groups_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all(), required=False
    )

    class Meta:
        model = models.List
        fields = [
            'id', 'name', 'type',
            'user_groups',      # ✅ GET → [{id, name}]
            'user_groups_ids',  # ✅ POST/PUT/PATCH → [1,2]
            'description', 'values'
        ]

    def to_representation(self, instance):
        """Add user_groups_ids to GET response"""
        data = super().to_representation(instance)
        data['user_groups_ids'] = list(instance.user_groups.values_list('id', flat=True))
        return data

    def create(self, validated_data):
        values_data = validated_data.pop('values', [])
        user_groups = validated_data.pop('user_groups_ids', [])

        list_obj = models.List.objects.create(**validated_data)
        list_obj.user_groups.set(user_groups)

        for value_data in values_data:
            models.Value.objects.create(list=list_obj, **value_data)

        return list_obj

    def update(self, instance, validated_data):
        values_data = validated_data.pop('values', None)
        user_groups = validated_data.pop('user_groups_ids', None)

        # Update main List fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # ✅ Update M2M if provided
        if user_groups is not None:
            instance.user_groups.set(user_groups)

        # ✅ Update or create values
        if values_data is not None:
            existing_ids = {v.id: v for v in instance.values.all()}
            sent_ids = []

            for value_data in values_data:
                value_id = value_data.pop('id', None)

                if value_id and value_id in existing_ids:
                    value_obj = existing_ids[value_id]
                    for attr, val in value_data.items():
                        setattr(value_obj, attr, val)
                    value_obj.save()
                    sent_ids.append(value_id)
                else:
                    new_value = models.Value.objects.create(list=instance, **value_data)
                    sent_ids.append(new_value.id)

            # Optional: delete records not sent
            for val_id, val_obj in existing_ids.items():
                if val_id not in sent_ids:
                    val_obj.delete()

        return instance


class SampleFieldSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)

    class Meta:
        model = models.SampleField
        fields = [
            'id', 'field_name', 'field_property', 'list_ref',
            'link_to_table', 'order', 'required'
        ]


class SampleFormSerializer(serializers.ModelSerializer):
    fields = SampleFieldSerializer(many=True)

    # ✅ Read-only nested
    user_groups = UserGroupSerializer(many=True, read_only=True)
    group_analysis_list = AnalysisSerializer(many=True, read_only=True)

    # ✅ Write-only IDs
    user_groups_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all(), required=False
    )
    group_analysis_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.Analysis.objects.all(), required=False
    )

    class Meta:
        model = models.SampleForm
        fields = [
            'id', 'sample_name', 'version',
            'group_analysis_list',   # ✅ GET nested analysis objects
            'group_analysis_ids',    # ✅ POST/PUT with IDs
            'user_groups',           # ✅ GET nested user groups
            'user_groups_ids',       # ✅ POST/PUT with IDs
            'description', 'fields'
        ]

    def to_representation(self, instance):
        """Add *_ids fields to GET response"""
        data = super().to_representation(instance)
        data['user_groups_ids'] = list(instance.user_groups.values_list('id', flat=True))
        data['group_analysis_ids'] = list(instance.group_analysis_list.values_list('id', flat=True))
        return data

    def create(self, validated_data):
        fields_data = validated_data.pop('fields', [])
        user_groups = validated_data.pop('user_groups_ids', [])
        group_analysis = validated_data.pop('group_analysis_ids', [])

        # Create form
        sample_form = models.SampleForm.objects.create(**validated_data)

        # Set many-to-many
        sample_form.user_groups.set(user_groups)
        sample_form.group_analysis_list.set(group_analysis)

        # Create related fields
        for field_data in fields_data:
            models.SampleField.objects.create(sample_form=sample_form, **field_data)

        return sample_form

    def update(self, instance, validated_data):
        fields_data = validated_data.pop('fields', None)
        user_groups = validated_data.pop('user_groups_ids', None)
        group_analysis = validated_data.pop('group_analysis_ids', None)

        # Update basic form fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update M2M if provided
        if user_groups is not None:
            instance.user_groups.set(user_groups)
        if group_analysis is not None:
            instance.group_analysis_list.set(group_analysis)

        # Update / create / delete nested fields
        if fields_data is not None:
            existing_fields = {field.id: field for field in instance.fields.all()}
            sent_ids = []

            for field_data in fields_data:
                field_id = field_data.pop('id', None)

                if field_id and field_id in existing_fields:
                    # Update existing
                    field_instance = existing_fields[field_id]
                    for attr, value in field_data.items():
                        setattr(field_instance, attr, value)
                    field_instance.save()
                    sent_ids.append(field_id)
                else:
                    # Create new
                    new_field = models.SampleField.objects.create(sample_form=instance, **field_data)
                    sent_ids.append(new_field.id)

            # Delete missing ones
            for field_id, field_obj in existing_fields.items():
                if field_id not in sent_ids:
                    field_obj.delete()

        return instance


class EntryAnalysisSerializer(serializers.Serializer):
    analysis_id = serializers.IntegerField()
    component_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )



class DynamicFormEntrySerializer(serializers.ModelSerializer):
    analyses_data = serializers.JSONField(write_only=True, required=False)
    logged_by_name = serializers.SerializerMethodField()
    form_name = serializers.SerializerMethodField()
    form_id = serializers.SerializerMethodField()
    analyst_name = serializers.SerializerMethodField()

    class Meta:
        model = models.DynamicFormEntry
        fields = [
            "id", "comment","form_name", "form_id", "data",
            "status", "analyses_data", "analyst_id", "analyst_name", "created_at", "logged_by", "logged_by_name"
        ]


    def get_form_name(self, obj):
        return obj.form.sample_name if obj.form else None

    def get_form_id(self, obj):
        return obj.form.id if obj.form else None
    
    def get_logged_by_name(self, obj):
        if obj.logged_by:
            return f"{obj.logged_by.name}".strip()
        return None
    
    def get_analyst_name(self, obj):
        if obj.analyst:
            return f"{obj.analyst.name}".strip()
        return None


    # -------------------------
    #   Create
    # -------------------------
    def create(self, validated_data):
        analyses_data = validated_data.pop("analyses_data", [])
        entry = super().create(validated_data)
        if analyses_data:
            self._save_entry_analyses(entry, analyses_data)
        return entry

    # -------------------------
    #   Update
    # -------------------------
    def update(self, instance, validated_data):
        request_data = self.context.get("request").data

        # ✅ 1️⃣ Handle Analyst Assignment First
        status = validated_data.get("status")
        analyst_id = validated_data.get("analyst_id")

        if status == "assign_analyst":
            if not analyst_id:
                raise serializers.ValidationError("Please provide an 'analyst_id' when assigning analyst.")

            try:
                analyst = models.User.objects.get(id=analyst_id)
            except models.User.DoesNotExist:
                raise serializers.ValidationError("Invalid 'analyst_id' provided.")

            # Prevent reassigning if already assigned
            if instance.analyst and instance.analyst.id != analyst.id:
                raise serializers.ValidationError("Analyst already assigned. Unassign before reassigning.")

            instance.analyst = analyst
            instance.status = "assign_analyst"
            instance.save(update_fields=["analyst", "status"])
            return instance

        # ✅ 2️⃣ Only allow data updates if status is "received"
        if instance.status != "received":
            raise serializers.ValidationError(
                f"Updates allowed only when sample status is 'received' (current: {instance.status})"
            )

        # ✅ Extract dynamic "data" fields
        if hasattr(request_data, "lists"):
            data_dict = {}
            for key, value in request_data.lists():
                if key.startswith("data[") and key.endswith("]"):
                    clean_key = key[5:-1]
                    data_dict[clean_key] = value if len(value) > 1 else value[0]
        else:
            data_dict = validated_data.get("data", {})

        # ✅ Merge and save data
        new_data = instance.data.copy() if instance.data else {}
        for key, value in data_dict.items():
            if hasattr(value, "read"):  # file upload
                file_name = default_storage.save(
                    f"uploads/sample/{value.name}",
                    ContentFile(value.read())
                )
                file_path = default_storage.url(file_name)
                new_data[key] = [file_path]
            else:
                new_data[key] = value

        instance.data = new_data

        # ✅ Allow explicit status update (e.g., received → in_progress etc.)
        if "status" in validated_data:
            instance.status = validated_data["status"]

        instance.save()

        # ✅ Handle analyses_data if provided
        analyses_data = request_data.get("analyses_data") or validated_data.get("analyses_data", [])
        if isinstance(analyses_data, str):
            try:
                analyses_data = json.loads(analyses_data)
            except Exception:
                analyses_data = []

        if analyses_data and isinstance(analyses_data, (list, dict)) and len(analyses_data) > 0:
            models.DynamicFormEntryAnalysis.objects.filter(entry=instance).delete()
            self._save_entry_analyses(instance, analyses_data)

        return instance

    # -------------------------
    #   Save Analyses
    # -------------------------
    def _save_entry_analyses(self, entry, analyses_data):
        for analysis_item in analyses_data:
            analysis_id = analysis_item["analysis_id"]
            component_ids = analysis_item.get("component_ids", [])
            analysis = models.Analysis.objects.get(id=analysis_id)

            # Ensure a single DynamicFormEntryAnalysis per entry+analysis
            ea, _ = models.DynamicFormEntryAnalysis.objects.get_or_create(
                entry=entry,
                analysis=analysis
            )

            # Set components
            if component_ids:
                components = models.Component.objects.filter(
                    id__in=component_ids,
                    analysis=analysis
                )
            else:
                components = analysis.components.all()

            ea.components.set(components)

            # 🔹 DELETE old SampleComponents for this entry_analysis first
            models.SampleComponent.objects.filter(entry_analysis=ea).delete()

            # 🔹 RECREATE sample components for this analysis
            old_to_new_sc_map = {}  # Keep mapping of old component -> new SampleComponent

            for comp in components:
                sc = models.SampleComponent.objects.create(
                    entry_analysis=ea,
                    component=comp,
                    name=comp.name,
                    unit=comp.unit,
                    minimum=comp.minimum,
                    maximum=comp.maximum,
                    decimal_places=comp.decimal_places,
                    rounding=comp.rounding,
                    spec_limits=comp.spec_limits,
                    description=comp.description,
                    optional=comp.optional,
                    calculated=comp.calculated,
                    custom_function=comp.custom_function if comp.calculated else None,
                )
                old_to_new_sc_map[comp.id] = sc

            # 🔹 Clone function parameters for calculated components
            for comp in components:
                if not comp.calculated:
                    continue

                # Get the new SampleComponent for this calculated component
                new_sc = old_to_new_sc_map.get(comp.id)
                if not new_sc:
                    continue

                # Clone parameters
                for param in comp.function_parameters.all():
                    # Map the old mapped_component to the new SampleComponent
                    mapped_sc = old_to_new_sc_map.get(param.mapped_component.id)
                    if mapped_sc:
                        models.SampleComponentFunctionParameter.objects.create(
                            sample_component=new_sc,
                            parameter=param.parameter,
                            mapped_sample_component=mapped_sc
                        )

    # -------------------------
    #   Representation
    # -------------------------
    def to_representation(self, instance):
        data = super().to_representation(instance)

        # Format uploaded files
        formatted_data = {}
        for key, value in instance.data.items():
            if isinstance(value, str) and value.startswith("uploads/sample/"):
                request = self.context.get("request")
                formatted_data[key] = request.build_absolute_uri(value) if request else value
            else:
                formatted_data[key] = value
        data["data"] = formatted_data

        # Include analyses + sample components
        entry_analyses = models.DynamicFormEntryAnalysis.objects.filter(
            entry=instance
        ).prefetch_related("components", "sample_components__component")

        analyses_data = []
        for ea in entry_analyses:
            components_data = []
            for sc in ea.sample_components.all():
                components_data.append({
                    "id": sc.component.id if sc.component else None,
                    "sample_id": sc.id,
                    "name": sc.name,
                    "unit": sc.unit.name if sc.unit else None,
                    "minimum": sc.minimum,
                    "maximum": sc.maximum,
                    "decimal_places": sc.decimal_places,
                    "rounding": sc.rounding,
                    "spec_limits": sc.spec_limits,
                    "description": sc.description,
                    "optional": sc.optional,
                    "calculated": sc.calculated,
                })
            analyses_data.append({
                "analysis_id": ea.analysis.id,
                "analysis_name": ea.analysis.name,
                "components": components_data
            })


        data["analyses_data"] = analyses_data
        return data



class SampleComponentSerializer(serializers.ModelSerializer):
    # Optional overrides for related objects
    unit_id = serializers.PrimaryKeyRelatedField(
        queryset=models.Unit.objects.all(),
        source="unit",
        required=False,
        allow_null=True
    )
    unit = serializers.StringRelatedField(read_only=True)

    component_id = serializers.PrimaryKeyRelatedField(
        queryset=models.Component.objects.all(),
        source="component",
        required=False,
        allow_null=True
    )
    component_name = serializers.CharField(source="component.name", read_only=True)

    type = serializers.ChoiceField(choices=choices.ComponentTypes.choices,required=False,allow_null=True)

    function_id = serializers.PrimaryKeyRelatedField(
        queryset=models.CustomFunction.objects.all(),
        source="custom_function",
        required=False,
        allow_null=True
    )
    function = CustomFunctionSerializer(source="custom_function", read_only=True)

    spec_limits = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True
    )

    rounding_display = serializers.CharField(source="get_rounding_display", read_only=True)
    parameters = serializers.SerializerMethodField()

    class Meta:
        model = models.SampleComponent
        fields = [
            "id",
            "entry_analysis",
            "component_id",
            "component_name",
            "name",
            "type",
            "unit_id",
            "unit",
            "minimum",
            "maximum",
            "decimal_places",
            "rounding",
            "rounding_display",
            "spec_limits",
            "description",
            "optional",
            "calculated",
            "function_id",
            "function",
            "parameters",
        ]

    def validate(self, attrs):
        comp_obj = attrs.get("component") or getattr(self.instance, "component", None)

        sample_type = attrs.get("type") or getattr(self.instance, "type", None)
        comp_type = sample_type or getattr(comp_obj, "type", None)

        if comp_type == choices.ComponentTypes.LIST:
            list_obj = getattr(comp_obj, "listname", None)
            if not list_obj:
                raise serializers.ValidationError(
                    {"component_id": "Component list is required for 'List' type."}
                )

            allowed_values = set(list_obj.values.values_list("value", flat=True))
            spec_limits = attrs.get("spec_limits")

            if not spec_limits:
                attrs["spec_limits"] = list(allowed_values)
            else:
                invalid = [val for val in spec_limits if val not in allowed_values]
                if invalid:
                    raise serializers.ValidationError({
                        "spec_limits": f"Invalid values for list '{list_obj.name}': {', '.join(invalid)}"
                    })

        return attrs

    def create(self, validated_data):
        parameters_data = self.initial_data.get("parameters", [])
        sample_component = models.SampleComponent.objects.create(**validated_data)

        if sample_component.calculated and sample_component.custom_function:
            expected_vars = set(sample_component.custom_function.variables)
            provided_vars = {p["parameter"] for p in parameters_data}

            missing = expected_vars - provided_vars
            if missing:
                raise serializers.ValidationError(
                    {"parameters": f"Missing mappings for variables: {', '.join(missing)}"}
                )

            extra = provided_vars - expected_vars
            if extra:
                raise serializers.ValidationError(
                    {"parameters": f"Unexpected variables: {', '.join(extra)}"}
                )

            for param in parameters_data:
                var_name = param["parameter"]
                mapped_id = param["mapped_sample_component"]

                try:
                    mapped_component = models.SampleComponent.objects.get(id=mapped_id)
                except models.SampleComponent.DoesNotExist:
                    raise serializers.ValidationError(
                        {"parameters": f"SampleComponent {mapped_id} not found"}
                    )

                models.SampleComponentFunctionParameter.objects.create(
                    sample_component=sample_component,
                    parameter=var_name,
                    mapped_sample_component=mapped_component
                )

        return sample_component

    def update(self, instance, validated_data):
        parameters_data = self.initial_data.get("parameters", [])

        # Update regular fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if instance.calculated and instance.custom_function and parameters_data:
            # Fetch existing parameters for this sample component
            existing_params = {p.parameter: p for p in instance.function_parameters.all()}

            expected_vars = set(instance.custom_function.variables)
            provided_vars = {p["parameter"] for p in parameters_data}

            missing = expected_vars - provided_vars
            if missing:
                raise serializers.ValidationError(
                    {"parameters": f"Missing mappings for variables: {', '.join(missing)}"}
                )

            extra = provided_vars - expected_vars
            if extra:
                raise serializers.ValidationError(
                    {"parameters": f"Unexpected variables: {', '.join(extra)}"}
                )

            # Update existing or create new
            for param in parameters_data:
                var_name = param["parameter"]
                mapped_id = param["mapped_sample_component"]

                try:
                    mapped_component = models.SampleComponent.objects.get(id=mapped_id)
                except models.SampleComponent.DoesNotExist:
                    raise serializers.ValidationError(
                        {"parameters": f"SampleComponent {mapped_id} not found"}
                    )

                if var_name in existing_params:
                    # Update existing mapping
                    fp = existing_params[var_name]
                    fp.mapped_sample_component = mapped_component
                    fp.save()
                else:
                    # Create new mapping
                    models.SampleComponentFunctionParameter.objects.create(
                        sample_component=instance,
                        parameter=var_name,
                        mapped_sample_component=mapped_component
                    )

        return instance


    def get_parameters(self, obj):
        if obj.calculated and obj.custom_function:
            var_order = obj.custom_function.variables
            mapping = {p.parameter: p for p in obj.function_parameters.all()}

            result = []
            for var_name in var_order:
                param_obj = mapping.get(var_name)

                if not param_obj:
                    # Return null mapping instead of crashing
                    result.append({
                        "parameter": var_name,
                        "mapped_sample_component": None
                    })
                    continue

                mapped = param_obj.mapped_sample_component

                result.append({
                    "parameter": var_name,
                    "mapped_sample_component": {
                        "id": mapped.id,
                        "name": mapped.name or mapped.component.name,
                    }
                })

            return result

        return []




class FileOrURLField(serializers.Field):
    def to_internal_value(self, data):
        # Case 1: Actual file upload (InMemoryUploadedFile, TemporaryUploadedFile)
        if isinstance(data, UploadedFile):
            return data

        # Case 2: URL string
        if isinstance(data, str):
            return data

        raise serializers.ValidationError("This field must be a file or a URL string.")

    def to_representation(self, value):
        # If value is file (FileField or InMemoryUploadedFile)
        try:
            return value.url
        except AttributeError:
            # If already a string (URL)
            return value


def build_dynamic_serializer(fields):
    field_dict = {}
    for field in fields:
        if field.link_to_table:
            if '_' in field.link_to_table:
                app_label, model_snake = field.link_to_table.split('_', 1)
                model_name = inflection.camelize(model_snake)
            else:
                app_label = 'app'
                model_name = inflection.camelize(field.link_to_table)

            linked_model = apps.get_model(app_label, model_name)
            choices = [(obj.id, str(obj)) for obj in linked_model.objects.all()]

            field_dict[field.field_name] = serializers.ChoiceField(
                choices=choices,
                required=bool(choices),
                allow_null=not bool(choices),
            )

        elif field.field_property == "text":
            field_dict[field.field_name] = serializers.CharField(required=True)

        elif field.field_property == "date_time":
            field_dict[field.field_name] = serializers.DateTimeField(required=True)

        elif field.field_property == "list" and field.list_ref:
            list_obj = field.list_ref
            choices = [(v.id, str(v)) for v in list_obj.values.all()]
            field_dict[field.field_name] = serializers.ChoiceField(
                choices=choices,
                required=bool(choices),
                allow_null=not bool(choices),
            )

        elif field.field_property == "attachment":
            # ✅ accept both file and URL
            field_dict[field.field_name] = serializers.ListField(
                child=FileOrURLField(),
                required=field.required,
                allow_empty=not field.required
            )

        else:
            # Fallback
            field_dict[field.field_name] = serializers.CharField(
                required=False,
                allow_blank=True
            )

    return type('DynamicSerializer', (serializers.Serializer,), field_dict)


class RequestFieldSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)

    class Meta:
        model = models.RequestField
        fields = [
            "id", "field_name", "field_property",
            "list_ref", "link_to_table", "order", "required"
        ]


class RequestFormSerializer(serializers.ModelSerializer):
    fields = RequestFieldSerializer(many=True)

    user_groups = UserGroupSerializer(many=True, read_only=True)

    user_groups_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all(), required=False
    )

    customer_name = serializers.PrimaryKeyRelatedField(queryset=models.Customer.objects.all())

    sample_form = SampleFormSerializer(many=True, read_only=True)

    sample_form_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.SampleForm.objects.all(), required=False
    )

    class Meta:
        model = models.RequestForm
        fields = [
            "id", "request_name", "version", "request_type",
            "sample_form", "sample_form_ids", "customer_name",
            "user_groups", "user_groups_ids",
            "description", "fields"
        ]

    def to_representation(self, instance):
        """Add *_ids to GET response"""
        data = super().to_representation(instance)
        data['user_groups_ids'] = list(instance.user_groups.values_list('id', flat=True))
        data['sample_form_ids'] = list(instance.sample_form.values_list('id', flat=True))
        return data

    def create(self, validated_data):
        fields_data = validated_data.pop("fields", [])
        user_groups = validated_data.pop("user_groups_ids", [])
        sample_forms = validated_data.pop("sample_form_ids", [])

        request_form = models.RequestForm.objects.create(**validated_data)
        request_form.user_groups.set(user_groups)
        request_form.sample_form.set(sample_forms)

        for field_data in fields_data:
            models.RequestField.objects.create(request_form=request_form, **field_data)

        return request_form

    def update(self, instance, validated_data):
        fields_data = validated_data.pop("fields", None)
        user_groups = validated_data.pop("user_groups_ids", None)
        sample_forms = validated_data.pop("sample_form_ids", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if user_groups is not None:
            instance.user_groups.set(user_groups)

        if sample_forms is not None:
            instance.sample_form.set(sample_forms)

        if fields_data is not None:
            existing_fields = {field.id: field for field in instance.fields.all()}
            sent_ids = []

            for field_data in fields_data:
                field_id = field_data.pop("id", None)

                if field_id and field_id in existing_fields:
                    field_instance = existing_fields[field_id]
                    for attr, value in field_data.items():
                        setattr(field_instance, attr, value)
                    field_instance.save()
                    sent_ids.append(field_id)
                else:
                    new_field = models.RequestField.objects.create(request_form=instance, **field_data)
                    sent_ids.append(new_field.id)

            for field_id, field_obj in existing_fields.items():
                if field_id not in sent_ids:
                    field_obj.delete()

        return instance


def build_dynamic_request_serializer(fields):
    field_dict = {}
    for field in fields:
        if field.link_to_table:
            if '_' in field.link_to_table:
                app_label, model_snake = field.link_to_table.split('_', 1)
                model_name = inflection.camelize(model_snake)
            else:
                app_label = 'app'
                model_name = inflection.camelize(field.link_to_table)

            linked_model = apps.get_model(app_label, model_name)
            choices = [(obj.id, str(obj)) for obj in linked_model.objects.all()]

            field_dict[field.field_name] = serializers.ChoiceField(
                choices=choices,
                required=field.required,
                allow_null=not field.required
            )

        elif field.field_property == "text":
            field_dict[field.field_name] = serializers.CharField(required=field.required)

        elif field.field_property == "date_time":
            field_dict[field.field_name] = serializers.DateTimeField(required=field.required)

        elif field.field_property == "list" and field.list_ref:
            list_obj = field.list_ref
            valid_ids = list_obj.values.values_list("id", flat=True)

            # Custom field to validate IDs
            class ListIDField(serializers.IntegerField):
                def to_internal_value(self, data):
                    data = super().to_internal_value(data)
                    if data not in valid_ids:
                        raise serializers.ValidationError(
                            f"Invalid ID {data}. This ID does not exist in list '{list_obj.name}'."
                        )
                    return data

            field_dict[field.field_name] = serializers.ListField(
                child=ListIDField(),
                required=field.required,
                allow_empty=not field.required
            )

        elif field.field_property == "attachment":
            # ✅ Hybrid: accept either file uploads OR URLs
            field_dict[field.field_name] = serializers.ListField(
                child=serializers.CharField(),  # string for URLs
                required=field.required,
                allow_empty=not field.required
            )

        else:
            field_dict[field.field_name] = serializers.CharField(
                required=field.required, allow_blank=not field.required
            )

    return type('DynamicRequestSerializer', (serializers.Serializer,), field_dict)

# ------------------ Serializers ------------------
class DynamicFormAttachmentSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    file_path = serializers.SerializerMethodField()

    class Meta:
        model = models.DynamicFormAttachment
        fields = ["id", "field", "file", "file_url", "file_path"]

    def get_file_url(self, obj):
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(obj.file.url)
        return obj.file.url

    def get_file_path(self, obj):
        return obj.file.path




class DynamicRequestAttachmentSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    file_path = serializers.SerializerMethodField()

    class Meta:
        model = models.DynamicRequestAttachment
        fields = ["id", "field", "file", "file_url", "file_path"]

    def get_file_url(self, obj):
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(obj.file.url)
        return obj.file.url

    def get_file_path(self, obj):
        return obj.file.path



class DynamicRequestEntrySerializer(serializers.ModelSerializer):
    form_name = serializers.CharField(source="request_form.request_name", read_only=True)
    logged_by_name = serializers.CharField(source="logged_by.name", read_only=True)
    analyst_name = serializers.CharField(source="analyst.name", read_only=True)

    request_form_attachments = serializers.SerializerMethodField()
    sample_forms = serializers.SerializerMethodField()
    form_id = serializers.IntegerField(source="request_form.id", read_only=True)

    class Meta:
        model = models.DynamicRequestEntry
        fields = [
            "id", "form_name", "form_id", "data", "analyst_name",
            "logged_by_name", "created_at", "status",
            "request_form_attachments", "sample_forms", "comment"
        ]

    def get_request_form_attachments(self, obj):
        attachments = obj.attachments.filter(
            entry=obj, field__field_property="attachment"
        )
        return DynamicRequestAttachmentSerializer(
            attachments, many=True, context=self.context
        ).data

    def get_sample_forms(self, obj):
        sample_list = obj.data.get("sample_forms", [])
        sample_ids = [entry.get("id") for entry in sample_list if "id" in entry]

        entries = models.DynamicFormEntry.objects.filter(id__in=sample_ids)
        return DynamicFormEntrySerializer(
            entries, many=True, context=self.context
        ).data




class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Customer
        fields = '__all__'

    def validate_mobile(self, value):
        try:
            parsed = phonenumbers.parse(value, None)
            if not phonenumbers.is_valid_number(parsed):
                raise serializers.ValidationError("Invalid phone number format.")
        except phonenumbers.NumberParseException:
            raise serializers.ValidationError("Invalid phone number. Use format like +14155552671.")
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)


class SamplingPointSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.SamplingPoint
        fields = ['id', 'name']

class GradeSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Grade
        fields = ['id', 'name']



class ProductSamplingGradeAnalysisSerializer(serializers.Serializer):
    analysis_id = serializers.IntegerField()
    component_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False
    )


class ProductSamplingGradeSerializer(serializers.Serializer):
    sampling_point_id = serializers.IntegerField()
    grade_id = serializers.IntegerField()
    analyses = ProductSamplingGradeAnalysisSerializer(many=True)


class ProductSerializer(serializers.ModelSerializer):
    user_groups = UserGroupSerializer(many=True, read_only=True)

    user_groups_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=models.UserGroup.objects.all(),
        required=False
    )

    analyses_data = ProductSamplingGradeSerializer(
        many=True,
        write_only=True,
        required=False
    )

    class Meta:
        model = models.Product
        fields = [
            "id",
            "name",
            "version",
            "description",
            "user_groups",
            "user_groups_ids",
            "analyses_data",
        ]

    # ----------------------------
    # CREATE
    # ----------------------------
    def create(self, validated_data):
        analyses_data = validated_data.pop("analyses_data", [])
        user_groups = validated_data.pop("user_groups_ids", [])

        product = models.Product.objects.create(**validated_data)
        product.user_groups.set(user_groups)

        self._save_sampling_grade_analyses(product, analyses_data)
        return product

    # ----------------------------
    # UPDATE / PATCH
    # ----------------------------
    def update(self, instance, validated_data):
        analyses_data = validated_data.pop("analyses_data", None)
        user_groups = validated_data.pop("user_groups_ids", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if user_groups is not None:
            instance.user_groups.set(user_groups)

        if analyses_data is not None:
            for psg in instance.sampling_grades.all():
                for pa in psg.analyses.all():
                    pa.sample_components.clear()
                    pa.delete()
                psg.delete()

            self._save_sampling_grade_analyses(instance, analyses_data)

        return instance

    # ----------------------------
    # SAVE STRUCTURE
    # ----------------------------
    def _save_sampling_grade_analyses(self, product, analyses_data):
        for sg in analyses_data:
            sampling_point = models.SamplingPoint.objects.get(
                id=sg["sampling_point_id"]
            )
            grade = models.Grade.objects.get(
                id=sg["grade_id"]
            )

            psg = models.ProductSamplingGrade.objects.create(
                product=product,
                sampling_point=sampling_point,
                grade=grade,
            )

            for analysis_item in sg["analyses"]:
                self._save_analysis(psg, analysis_item)

    def _save_analysis(self, psg, analysis_item):
        analysis = models.Analysis.objects.get(
            id=analysis_item["analysis_id"]
        )

        pa = models.ProductSamplingGradeAnalysis.objects.create(
            product_sampling_grade=psg,
            analysis=analysis
        )

        component_ids = analysis_item.get("component_ids", [])
        if component_ids:
            self._create_sample_component_replicas(pa, component_ids)

    # ----------------------------
    # CREATE SampleComponent replicas
    # ----------------------------
    def _create_sample_component_replicas(self, pa, component_ids):
        replica_map = {}

        for cid in component_ids:
            real = models.Component.objects.get(id=cid)
            replica = models.SampleComponent.objects.create(
                entry_analysis=None,
                component=real,
                name=real.name,
                unit=real.unit,
                minimum=real.minimum,
                maximum=real.maximum,
                decimal_places=real.decimal_places,
                rounding=real.rounding,
                description=real.description,
                optional=real.optional,
                calculated=real.calculated,
                spec_limits=real.spec_limits,
                custom_function=real.custom_function if real.calculated else None,
            )
            replica_map[real.id] = replica

        for real in models.Component.objects.filter(id__in=component_ids):
            replica = replica_map[real.id]
            for fp in real.function_parameters.all():
                mapped_real = fp.mapped_component
                mapped_replica = replica_map.get(mapped_real.id) if mapped_real else None
                if mapped_real and mapped_replica:
                    models.SampleComponentFunctionParameter.objects.create(
                        sample_component=replica,
                        parameter=fp.parameter,
                        mapped_sample_component=mapped_replica,
                    )

        pa.sample_components.set(replica_map.values())

    # ----------------------------
    # GET RESPONSE
    # ----------------------------
    def to_representation(self, instance):
        data = super().to_representation(instance)

        data["user_groups_ids"] = list(
            instance.user_groups.values_list("id", flat=True)
        )

        analyses_output = []

        for psg in instance.sampling_grades.all():
            for pa in psg.analyses.all():
                analyses_output.append({
                    "sampling_point_id": psg.sampling_point.id,
                    "sampling_point_name": psg.sampling_point.name,
                    "grade_id": psg.grade.id,
                    "grade_name": psg.grade.name,
                    "analysis_id": pa.analysis.id,
                    "analysis_name": pa.analysis.name if hasattr(pa.analysis, 'name') else str(pa.analysis),
                    "component_ids": list(pa.sample_components.values_list("component_id", flat=True)),
                    "sample_component_ids": list(pa.sample_components.values_list("id", flat=True))
                })

        data["analyses_data"] = analyses_output
        return data


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Permission
        fields = ["id", "module", "action"]

    def validate_module(self, value):
        """Check if the given module (table name) exists in DB"""
        all_tables = [m._meta.db_table for m in apps.get_models()]
        if value not in all_tables:
            raise serializers.ValidationError(f"Invalid module '{value}'. Table does not exist in DB.")
        return value


class RoleSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True)
    users = serializers.PrimaryKeyRelatedField(
        queryset=models.User.objects.all(), many=True, write_only=True
    )
    users_detail = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.Role
        fields = ["id", "name", "users", "users_detail", "permissions"]

    def get_users_detail(self, obj):
        return [{"id": user.id, "username": user.username} for user in obj.users.all()]

    def create(self, validated_data):
        users = validated_data.pop("users", [])
        permissions_data = validated_data.pop("permissions", [])
        role = models.Role.objects.create(**validated_data)
        role.users.set(users)

        for perm in permissions_data:
            models.Permission.objects.create(role=role, **perm)
        return role

    def update(self, instance, validated_data):
        users = validated_data.pop("users", [])
        permissions_data = validated_data.pop("permissions", [])

        instance.name = validated_data.get("name", instance.name)
        instance.save()
        instance.users.set(users)

        instance.permissions.all().delete()
        for perm in permissions_data:
            models.Permission.objects.create(role=instance, **perm)

        return instance


class AnalysisSchemaSerializer(serializers.ModelSerializer):
    components = ComponentSerializer(many=True)

    class Meta:
        model = models.Analysis
        fields = ["id", "name", "components"]




class ComponentResultSerializer(serializers.ModelSerializer):
    sample_component_name = serializers.CharField(source="sample_component.name", read_only=True)
    component_type = serializers.CharField(source="sample_component.component.type", read_only=True)
    spec_limits = serializers.SerializerMethodField()

    class Meta:
        model = models.ComponentResult
        fields = [
            "id",
            "sample_component",
            "sample_component_name",
            "component_type",
            "value",
            "numeric_value",
            "remarks",
            "created_by",
            "spec_limits",
            "authorization_flag",
            "authorization_remark",
        ]

    def get_spec_limits(self, obj):
        if obj.sample_component.component.type == ComponentTypes.LIST:
            return obj.sample_component.spec_limits or []


class SystemConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.SystemConfiguration
        fields = ["id", "key", "value", "updated_at"]


class BulkConfigUpdateSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    value = serializers.CharField(max_length=255)


class ReportDefinitionSerializer(serializers.Serializer):
    app_label = serializers.CharField()
    model = serializers.CharField()
    date_field = serializers.CharField()
    group_by = serializers.ListField(child=serializers.CharField(), required=False)
    columns = serializers.ListField()
    date_from = serializers.DateField(required=False)
    date_to = serializers.DateField(required=False)


class MultiReportSerializer(serializers.Serializer):
    reports = ReportDefinitionSerializer(many=True)


class ActivitySerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source="user.name", read_only=True)

    class Meta:
        model = models.Activity
        fields = '__all__'


class ReportTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ReportTemplate
        fields = ["id", "name", "html_content", "css_content", "fields", "created_at"]


class QueryReportTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.QueryReportTemplate
        fields = ["id","name","html_content","css_content","sql_query","parameters","output_format", "created_at", "updated_at"]


class AddCommentSerializer(serializers.Serializer):
    comment = serializers.CharField(required=True)


