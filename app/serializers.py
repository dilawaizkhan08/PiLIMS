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
        fields = '__all__'

    def create(self, validated_data):
        request = self.context.get('request')
        password = validated_data.pop('password')

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
    
    def validate_username(self, value):
        if models.User.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

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



class UserGroupSerializer(serializers.ModelSerializer):
    users = serializers.PrimaryKeyRelatedField(queryset=models.User.objects.all(), many=True)

    class Meta:
        model = models.UserGroup
        fields = ['id', 'name', 'users']



class ComponentSerializer(serializers.ModelSerializer):
    analysis_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = models.Component
        fields = [
            'id', 'analysis_id', 'name', 'type', 'unit', 'spec_limits', 'description',
            'optional', 'calculated', 'minimum', 'maximum',
            'rounding', 'decimal_places', 'listname'
        ]

    def create(self, validated_data):
        analysis_id = validated_data.pop("analysis_id")
        try:
            analysis = models.Analysis.objects.get(id=analysis_id)
        except models.Analysis.DoesNotExist:
            raise serializers.ValidationError("Analysis with given ID does not exist.")
        
        return models.Component.objects.create(analysis=analysis, **validated_data)


class AnalysisAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.AnalysisAttachment
        fields = ['id', 'file']



class AnalysisSerializer(serializers.ModelSerializer):
    attachments = AnalysisAttachmentSerializer(many=True, read_only=True)
    components = ComponentSerializer(many=True, read_only=True)

    # ✅ Instead of PrimaryKeyRelatedField, use nested serializer for GET
    user_groups = UserGroupSerializer(many=True, read_only=True)

    # ✅ Allow writing user_groups by ID (for POST/PUT)
    user_groups_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all(), write_only=True
    )

    class Meta:
        model = models.Analysis
        fields = [
            "id",
            "name",
            "version",
            "alias_name",
            "user_groups",      # returns {id, name}
            "user_groups_ids",  # accepts IDs for write
            "type",
            "test_method",
            "price",
            "description",
            "attachments",
            "components",
        ]

    def create(self, validated_data):
        user_groups = validated_data.pop("user_groups_ids", [])
        analysis = models.Analysis.objects.create(**validated_data)
        analysis.user_groups.set(user_groups)
        return analysis

    def update(self, instance, validated_data):
        user_groups = validated_data.pop("user_groups_ids", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if user_groups is not None:
            instance.user_groups.set(user_groups)
        return instance
    



class CustomFunctionSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.CustomFunction
        fields = ['id', 'name', 'variables', 'script']



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

class InstrumentSerializer(serializers.ModelSerializer):
    history = InstrumentHistorySerializer(many=True)
    user_groups = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all()
    )

    class Meta:
        model = models.Instrument
        fields = [
            'id', 'created_at', 'updated_at', 'is_deleted',
            'name', 'vendor', 'manufacturer', 'serial_no', 'model_no',
            'description', 'calibration_period', 'next_calibration_date',
            'prevention_period', 'next_prevention_date',
            'user_groups',   # ✅ handle M2M
            'history'
        ]

    def create(self, validated_data):
        history_data = validated_data.pop('history', [])
        user_groups = validated_data.pop('user_groups', [])

        instrument = models.Instrument.objects.create(**validated_data)
        instrument.user_groups.set(user_groups)  # ✅ assign M2M

        for hist in history_data:
            models.InstrumentHistory.objects.create(instrument=instrument, **hist)

        return instrument

    def update(self, instance, validated_data):
        history_data = validated_data.pop('history', None)
        user_groups = validated_data.pop('user_groups', None)

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
    user_groups = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all()
    )
    user_group_names = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.Inventory
        fields = [
            'id', 'name', 'type',
            'user_groups',        # ✅ accept IDs
            'user_group_names',   # ✅ show names in response
            'location', 'unit', 'total_quantity',
            'description', 'stocks'
        ]

    def get_user_group_names(self, obj):
        return [ug.name for ug in obj.user_groups.all()]

    def create(self, validated_data):
        stocks_data = validated_data.pop('stocks', [])
        user_groups = validated_data.pop('user_groups', [])

        inventory = models.Inventory.objects.create(**validated_data)
        inventory.user_groups.set(user_groups)  # ✅ assign M2M

        for stock_data in stocks_data:
            models.Stock.objects.create(inventory=inventory, **stock_data)

        return inventory

    def update(self, instance, validated_data):
        stocks_data = validated_data.pop('stocks', None)
        user_groups = validated_data.pop('user_groups', None)

        # Update inventory fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if user_groups is not None:
            instance.user_groups.set(user_groups)  # ✅ update M2M

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
        user_groups = validated_data.pop("user_groups", [])
        unit = models.Unit.objects.create(**validated_data)
        unit.user_groups.set(user_groups)  # ✅ assign M2M
        return unit

    def update(self, instance, validated_data):
        user_groups = validated_data.pop("user_groups", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if user_groups is not None:
            instance.user_groups.set(user_groups)  # ✅ update M2M
        return instance


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Customer
        fields = ['id', 'name']




class ValueSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)

    class Meta:
        model = models.Value
        fields = ['id', 'value']


class ListSerializer(serializers.ModelSerializer):
    values = ValueSerializer(many=True)

    class Meta:
        model = models.List
        fields = ['id', 'name', 'type', 'user_group', 'description', 'values']

    def create(self, validated_data):
        values_data = validated_data.pop('values', [])
        list_obj = models.List.objects.create(**validated_data)

        for value_data in values_data:
            models.Value.objects.create(list=list_obj, **value_data)

        return list_obj

    def update(self, instance, validated_data):
        values_data = validated_data.pop('values', None)

        # Update main List fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if values_data is not None:
            existing_ids = {v.id: v for v in instance.values.all()}
            sent_ids = []

            for value_data in values_data:
                value_id = value_data.pop('id', None)  # remove id so create doesn't get it

                if value_id and value_id in existing_ids:
                    # Update existing record
                    value_obj = existing_ids[value_id]
                    for attr, val in value_data.items():
                        setattr(value_obj, attr, val)
                    value_obj.save()
                    sent_ids.append(value_id)
                else:
                    # Create new record without id
                    new_value = models.Value.objects.create(list=instance, **value_data)
                    sent_ids.append(new_value.id)

            # Optional: delete records not sent in payload
            for val_id, val_obj in existing_ids.items():
                if val_id not in sent_ids:
                    val_obj.delete()

        return instance




from django.apps import apps



class SampleFieldSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)

    class Meta:
        model = models.SampleField
        fields = ['id', 'field_name', 'field_property', 'list_ref', 'link_to_table', 'order', 'required']


class SampleFormSerializer(serializers.ModelSerializer):
    fields = SampleFieldSerializer(many=True)
    user_groups = serializers.PrimaryKeyRelatedField(many=True, queryset=models.UserGroup.objects.all())

    class Meta:
        model = models.SampleForm
        fields = ['id', 'sample_name', 'version', 'group_analysis_list', 'user_groups', 'description', 'fields']

    def create(self, validated_data):
        fields_data = validated_data.pop('fields', [])
        user_groups = validated_data.pop('user_groups', [])

        # Create form
        sample_form = models.SampleForm.objects.create(**validated_data)

        # Set many-to-many
        sample_form.user_groups.set(user_groups)

        # Create related fields
        for field_data in fields_data:
            models.SampleField.objects.create(sample_form=sample_form, **field_data)

        return sample_form

    def update(self, instance, validated_data):
        fields_data = validated_data.pop('fields', [])
        user_groups = validated_data.pop('user_groups', None)

        # Update basic form fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update M2M if provided
        if user_groups is not None:
            instance.user_groups.set(user_groups)

        # Existing fields lookup
        existing_fields = {field.id: field for field in instance.fields.all()}

        for field_data in fields_data:
            field_id = field_data.get('id', None)

            if field_id and field_id in existing_fields:
                # Update
                field_instance = existing_fields[field_id]
                for attr, value in field_data.items():
                    if attr != 'id':
                        setattr(field_instance, attr, value)
                field_instance.save()
            else:
                # Create new
                models.SampleField.objects.create(sample_form=instance, **field_data)

        return instance


class DynamicFormEntrySerializer(serializers.ModelSerializer):
    form_name = serializers.CharField(source="form.sample_name", read_only=True)
    logged_by_name = serializers.CharField(source="logged_by.username", read_only=True)
    analyst_name = serializers.CharField(source="analyst.username", read_only=True)
    analyses = serializers.PrimaryKeyRelatedField(
        queryset=models.Analysis.objects.all(), many=True, required=False
    )

    class Meta:
        model = models.DynamicFormEntry
        fields = [
            "id", "form_name", "data", "status", 
            "analyst_name", "logged_by_name", "created_at",
            "analyses"
        ]


import inflection

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

            # Allow null and not required if no choices
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

        else:
            # Fallback for unknown field_property, make it optional CharField
            field_dict[field.field_name] = serializers.CharField(required=False, allow_blank=True)

    return type('DynamicSerializer', (serializers.Serializer,), field_dict)




class RequestFieldSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)

    class Meta:
        model = models.RequestField
        fields = ['id', 'field_name', 'field_property', 'list_ref', 'link_to_table', 'order', 'required']


class RequestFormSerializer(serializers.ModelSerializer):
    fields = RequestFieldSerializer(many=True)
    user_groups = serializers.PrimaryKeyRelatedField(many=True, queryset=models.UserGroup.objects.all())
    customer_name = serializers.PrimaryKeyRelatedField(queryset=models.Customer.objects.all())

    class Meta:
        model = models.RequestForm
        fields = [
            'id', 'request_name', 'version', 'request_type',
            'sample_form', 'customer_name', 'user_groups', 'description', 'fields'
        ]

    def create(self, validated_data):
        fields_data = validated_data.pop('fields', [])
        user_groups = validated_data.pop('user_groups', [])
        
        request_form = models.RequestForm.objects.create(**validated_data)
        request_form.user_groups.set(user_groups)

        for field_data in fields_data:
            models.RequestField.objects.create(request_form=request_form, **field_data)

        return request_form

    def update(self, instance, validated_data):
        fields_data = validated_data.pop('fields', [])
        user_groups = validated_data.pop('user_groups', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if user_groups is not None:
            instance.user_groups.set(user_groups)

        existing_fields = {field.id: field for field in instance.fields.all()}

        for field_data in fields_data:
            field_id = field_data.get('id', None)

            if field_id and field_id in existing_fields:
                field_instance = existing_fields[field_id]
                for attr, value in field_data.items():
                    if attr != 'id':
                        setattr(field_instance, attr, value)
                field_instance.save()
            else:
                models.RequestField.objects.create(request_form=instance, **field_data)

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
            choices = [(str(v), str(v)) for v in list_obj.values.all()]
            field_dict[field.field_name] = serializers.ChoiceField(
                choices=choices,
                required=field.required,
                allow_null=not field.required
            )

        else:
            field_dict[field.field_name] = serializers.CharField(
                required=field.required, allow_blank=not field.required
            )

    return type('DynamicRequestSerializer', (serializers.Serializer,), field_dict)


class DynamicRequestEntrySerializer(serializers.ModelSerializer):
    form_name = serializers.CharField(source="request_form.request_name", read_only=True)
    logged_by_name = serializers.CharField(source="logged_by.username", read_only=True)
    analyst_name = serializers.CharField(source="analyst.username", read_only=True)

    class Meta:
        model = models.DynamicRequestEntry
        fields = [
            "id", "form_name", "data", "analyst_name",
            "logged_by_name", "created_at", "status"
        ]




class TestMethodSerializer(serializers.ModelSerializer):
    user_groups = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=models.UserGroup.objects.all()
    )
    user_group_names = serializers.SerializerMethodField()

    class Meta:
        model = models.TestMethod
        fields = ['id', 'name', 'description', 'user_groups', 'user_group_names']

    def get_user_group_names(self, obj):
        return [ug.name for ug in obj.user_groups.all()]



class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Customer
        fields = '__all__'


class ProductAnalysisSerializer(serializers.Serializer):
    analysis_id = serializers.IntegerField()
    component_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )


class ProductSerializer(serializers.ModelSerializer):
    analyses_data = ProductAnalysisSerializer(many=True, write_only=True)
    user_groups = serializers.PrimaryKeyRelatedField(
        many=True, queryset=models.UserGroup.objects.all()
    )

    class Meta:
        model = models.Product
        fields = ["name", "version", "user_groups", "description", "analyses_data"]

    def create(self, validated_data):
        analyses_data = validated_data.pop("analyses_data", [])
        user_groups = validated_data.pop("user_groups", [])

        product = models.Product.objects.create(**validated_data)
        product.user_groups.set(user_groups)  # ✅ assign M2M

        for analysis_item in analyses_data:
            analysis_id = analysis_item["analysis_id"]
            component_ids = analysis_item.get("component_ids", [])
            analysis = models.Analysis.objects.get(id=analysis_id)
            pa = models.ProductAnalysis.objects.create(product=product, analysis=analysis)
            if component_ids:
                components = models.Component.objects.filter(id__in=component_ids, analysis=analysis)
            else:
                components = analysis.components.all()
            pa.components.set(components)

        return product

    def to_representation(self, instance):
        data = super().to_representation(instance)
        product_analyses = models.ProductAnalysis.objects.filter(product=instance)
        data["analyses_data"] = [
            {
                "analysis_id": pa.analysis.id,
                "component_ids": list(pa.components.values_list('id', flat=True))
            }
            for pa in product_analyses
        ]
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
        many=True,
        queryset=models.User.objects.all()
    )

    class Meta:
        model = models.Role
        fields = ["id", "name", "users", "permissions"]

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

        # replace permissions
        instance.permissions.all().delete()
        for perm in permissions_data:
            models.Permission.objects.create(role=instance, **perm)

        return instance