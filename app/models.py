from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext as _
from django.db import models
from django.conf import settings
import uuid
from app import choices
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from . import choices



class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        abstract = True
        ordering = ["-id"]



class User(AbstractUser, BaseModel):
    username = models.CharField(max_length=150, unique=True, null=False, blank=False)
    email = models.EmailField(_("Email"), unique=True, null=False, blank=False)
    password = models.CharField(max_length=128, null=False, blank=False)
    name = models.CharField(_("Full Name"), max_length=255, null=False, blank=False)

    idle_time = models.DurationField(null=True, blank=True)
    dob = models.DateField(_("Date of Birth"), null=True, blank=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    profile_picture = models.ImageField(upload_to="profile_pictures/", null=True, blank=True)

    role = models.CharField(
        max_length=20,
        choices=choices.UserRole.choices,
        default=choices.UserRole.USER,
    )
    created_by = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.SET_NULL, related_name='created_users'
    )
    last_login = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    
    failed_login_attempts = models.PositiveIntegerField(default=0)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "username"]

    def __str__(self):
        return self.email

    

class UserGroup(BaseModel):
    name = models.CharField(max_length=255, unique=True)
    users = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='user_groups', blank=True)

    def __str__(self):
        return self.name


class TestMethod(BaseModel):
    name = models.CharField(max_length=255)
    user_groups = models.ManyToManyField(UserGroup, blank=True, related_name='test_methods')
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class Unit(BaseModel):
    name = models.CharField(max_length=255)  # Required
    symbol = models.CharField(max_length=50)  # Required
    user_groups = models.ManyToManyField(UserGroup,blank=True, related_name="units")
    description = models.TextField(blank=True, null=True)  # Optional

    def __str__(self):
        return self.name

class List(BaseModel):
    name = models.CharField(max_length=255)
    type =  models.CharField(max_length=20,choices=choices.ListType.choices,)
    user_groups = models.ManyToManyField(UserGroup, blank=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


# ===================== Analyses ====================

class Analysis(BaseModel):
    name = models.CharField(max_length=255)
    alias_name = models.CharField(max_length=255, null=True, blank=True)
    version = models.PositiveIntegerField(default=1)

    user_groups = models.ManyToManyField(UserGroup, null=True, blank=True)
    type =  models.CharField(max_length=255, null=True, blank=True)
    test_method = models.ForeignKey(TestMethod, on_delete=models.SET_NULL, null=True)
    price = models.FloatField(null=True, blank=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


class AnalysisAttachment(BaseModel):
    analysis = models.ForeignKey(
        Analysis,
        related_name='attachments',
        on_delete=models.CASCADE,
        null=True,    # allow NULL for now
        blank=True
    )
    file = models.FileField(upload_to='analysis_attachments/')

    def __str__(self):
        return self.file.name


class Component(BaseModel):
    analysis = models.ForeignKey(Analysis, related_name='components', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=50,choices=choices.ComponentTypes.choices)
    unit = models.ForeignKey(Unit, on_delete=models.SET_NULL, null=True, blank=True, related_name="components")
    spec_limits = models.JSONField(default=list, blank=True, null=True)
    description = models.TextField(null=True, blank=True)
    optional = models.BooleanField(default=False)
    calculated = models.BooleanField(default=False)

    minimum = models.FloatField(null=True, blank=True)
    maximum = models.FloatField(null=True, blank=True)
    rounding = models.IntegerField(
        choices=choices.RoundingChoices.choices,
        null=True,
        blank=True
    )
    decimal_places = models.IntegerField(null=True, blank=True)
    listname = models.ForeignKey(List, on_delete=models.SET_NULL, null=True, blank=True, related_name="components")

    custom_function = models.ForeignKey('CustomFunction',on_delete=models.SET_NULL,null=True,blank=True,related_name='components')

    def __str__(self):
        return f"{self.name} ({self.analysis.name})"


class ComponentFunctionParameter(BaseModel):
    component = models.ForeignKey(
        "Component",
        on_delete=models.CASCADE,
        related_name="function_parameters"
    )
    parameter = models.CharField(max_length=255)   # e.g. "a"
    mapped_component = models.ForeignKey(
        "Component",
        on_delete=models.CASCADE,
        related_name="used_in_functions"
    )

    class Meta:
        unique_together = ("component", "parameter")

# ============================================

# ========= Functions =====================

class CustomFunction(BaseModel):
    name = models.CharField(max_length=255, unique=True)
    variables = models.JSONField()
    script = models.TextField()

    def evaluate(self, **kwargs):
        # Prepare safe environment
        local_env = {**kwargs, "result": None}
        try:
            exec(self.script, {}, local_env)
        except Exception as e:
            raise ValueError(f"Error executing function: {e}")

        if "result" not in local_env:
            raise ValueError("Script must define a 'result' variable")
        return local_env["result"]

    def __str__(self):
        return self.name
    
# ==============================================

# =============  Instruments ==============

class Instrument(BaseModel):
    name = models.CharField(max_length=255)
    user_groups = models.ManyToManyField(UserGroup, blank=True, null=True,related_name='instruments_as_user_group')
    vendor = models.CharField(max_length=255)
    manufacturer = models.CharField(max_length=255, blank=True, null=True)  # 👈 New field added
    serial_no = models.CharField(max_length=255, blank=True, null=True)
    model_no = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    calibration_period = models.IntegerField(blank=True, null=True)  # in days
    next_calibration_date = models.DateField(blank=True, null=True)
    prevention_period = models.IntegerField(blank=True, null=True)   # in days
    next_prevention_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return self.name
    


class InstrumentHistory(BaseModel):
    instrument = models.ForeignKey(Instrument, on_delete=models.CASCADE, related_name='history')
    action_type = models.CharField(max_length=100,choices=choices.ActionType.choices)
    start_date = models.DateField()

    def __str__(self):
        return f"{self.instrument.name} - {self.action_type} on {self.start_date}"
    

# ================================== 




class Inventory(BaseModel):
    name = models.CharField(max_length=255)
    type =  models.CharField(max_length=255, null=True, blank=True)
    user_groups = models.ManyToManyField(UserGroup, blank=True, null=True)
    location = models.CharField(max_length=255)
    unit = models.ForeignKey('Unit', on_delete=models.SET_NULL, null=True)
    total_quantity = models.IntegerField(default=0)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class Stock(BaseModel):
    inventory = models.ForeignKey(Inventory, on_delete=models.CASCADE, related_name='stocks')
    stock_date = models.DateField(blank=True, null=True)
    expiration_date = models.DateField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    quantity = models.IntegerField()

    def __str__(self):
        return f"{self.inventory.name} - {self.quantity}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Update total quantity in inventory
        total = sum(stock.quantity for stock in self.inventory.stocks.all())
        self.inventory.total_quantity = total
        self.inventory.save()




class Value(BaseModel):
    list = models.ForeignKey(List, related_name='values', on_delete=models.CASCADE)
    value = models.CharField(max_length=255)

    def __str__(self):
        return self.value
    


class SampleForm(BaseModel):
    sample_name = models.CharField(max_length=255)
    version = models.IntegerField(default=1)
    group_analysis_list = models.ManyToManyField("Analysis", related_name="sample_forms", blank=True)
    user_groups = models.ManyToManyField(UserGroup, blank=True, related_name="sample_forms")
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.sample_name


class SampleField(BaseModel):
    FIELD_PROPERTY_CHOICES = [
        ('text', 'Text'),
        ('numeric', 'Numeric'),
        ('date_time', 'Date & Time'),
        ('list', 'List'),
        ('link_to_table', 'Link to Table'),
        ('attachment', 'Attachment'),
    ]

    sample_form = models.ForeignKey(SampleForm, on_delete=models.CASCADE, related_name="fields")
    field_name = models.CharField(max_length=255)
    field_property = models.CharField(max_length=50, choices=FIELD_PROPERTY_CHOICES)

    list_ref = models.ForeignKey(List, on_delete=models.SET_NULL, null=True, blank=True)  # if 'list'
    link_to_table = models.CharField(max_length=255, blank=True, null=True)  # if 'link_to_table'
    
    order = models.IntegerField(default=0)
    required = models.BooleanField(default=False) 

    def __str__(self):
        return f"{self.field_name} ({self.sample_form.sample_name})"



class DynamicFormEntryAnalysis(BaseModel):
    entry = models.ForeignKey("DynamicFormEntry", on_delete=models.CASCADE)
    analysis = models.ForeignKey("Analysis", on_delete=models.CASCADE)
    components = models.ManyToManyField("Component", blank=True)

    def __str__(self):
        return f"{self.entry.id} - {self.analysis.name}"


class DynamicFormEntry(BaseModel):
    STATUS_CHOICES = [
        ("initiated", "Initiated"),
        ("received", "Received"),
        ("completed", "Completed"),
        ("authorized", "Authorized"),
        ("rejected", "Rejected"),
        ("cancelled", "Cancelled"),
        ("restored", "Restored"),
    ]

    form = models.ForeignKey(SampleForm, on_delete=models.CASCADE)
    data = models.JSONField()

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="initiated")  # ✅ add this

    analyst = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="analyzed_samples"
    )
    logged_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="logged_samples"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    analyses = models.ManyToManyField("Analysis", through="DynamicFormEntryAnalysis", related_name="entries", blank=True)

    def __str__(self):
        return f"Entry {self.id} - {self.form.sample_name} ({self.status})"

def attachment_upload_path(instance, filename):
    return f"uploads/sample/{filename}"


class DynamicFormAttachment(models.Model):
    entry = models.ForeignKey(
        "DynamicFormEntry",
        on_delete=models.CASCADE,
        related_name="attachments"
    )
    field = models.ForeignKey("SampleField", on_delete=models.CASCADE)
    file = models.FileField(upload_to=attachment_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.field.field_name} - {self.file.name}"




class Customer(BaseModel):
    name = models.CharField(max_length=255)  # Required
    email = models.EmailField(unique=True)   # Required & unique
    mobile = models.CharField(max_length=20) # Required
    company_name = models.CharField(max_length=255)  # Required

    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.name} ({self.company_name})"
    

class RequestForm(BaseModel):
    REQUEST_TYPE_CHOICES = [
        ('urgent', 'Urgent'),
        ('normal', 'Normal'),
        ('internal', 'Internal'),
        ('external', 'External'),
    ]

    request_name = models.CharField(max_length=255)
    version = models.IntegerField(default=1)
    request_type = models.CharField(max_length=50, choices=REQUEST_TYPE_CHOICES)
    sample_form = models.ForeignKey(SampleForm, on_delete=models.CASCADE, related_name="request_forms")
    customer_name = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="requests")  # assumes Customer model exists
    user_groups = models.ManyToManyField(UserGroup, related_name="request_forms")
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.request_name


class RequestField(BaseModel):
    FIELD_PROPERTY_CHOICES = [
        ('text', 'Text'),
        ('numeric', 'Numeric'),
        ('date_time', 'Date & Time'),
        ('list', 'List'),
        ('link_to_table', 'Link to Table'),
        ('attachment', 'Attachment'),
    ]

    request_form = models.ForeignKey(RequestForm, on_delete=models.CASCADE, related_name="fields")
    field_name = models.CharField(max_length=255)
    field_property = models.CharField(max_length=50, choices=FIELD_PROPERTY_CHOICES)

    list_ref = models.ForeignKey(List, on_delete=models.SET_NULL, null=True, blank=True)  # if 'list'
    link_to_table = models.CharField(max_length=255, blank=True, null=True)  # if 'link_to_table'
    order = models.IntegerField(default=0)
    required = models.BooleanField(default=False)  # ✅ same as SampleField

    def __str__(self):
        return f"{self.field_name} ({self.request_form.request_name})"


class DynamicRequestEntry(BaseModel):
    STATUS_CHOICES = [
        ("initiated", "Initiated"),
        ("received", "Received"),
        ("completed", "Completed"),
        ("authorized", "Authorized"),
        ("rejected", "Rejected"),
        ("cancelled", "Cancelled"),
        ("restored", "Restored"),
    ]

    request_form = models.ForeignKey(RequestForm, on_delete=models.CASCADE)
    data = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="initiated") 

    analyst = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="analyzed_request"
    )
    logged_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="logged_request"
    )

    analyses = models.ManyToManyField("Analysis", related_name="requests_entries", blank=True)


class DynamicRequestAttachment(models.Model):
    entry = models.ForeignKey("DynamicRequestEntry", on_delete=models.CASCADE, related_name="attachments")
    field = models.ForeignKey("RequestField", on_delete=models.CASCADE)
    file = models.FileField(upload_to="uploads/request/")  # 👈 path set here

    def __str__(self):
        return f"{self.field.field_name} - {self.file.name}"



class Product(BaseModel):
    name = models.CharField(max_length=255)
    version = models.PositiveIntegerField(default=1)
    user_groups = models.ManyToManyField(UserGroup, blank=True, null=True)
    description = models.TextField(blank=True)

    analyses = models.ManyToManyField('Analysis', through='ProductAnalysis')

    def __str__(self):
        return self.name


class ProductAnalysis(BaseModel):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE)
    components = models.ManyToManyField(Component, blank=True)

    def __str__(self):
        return f"{self.product.name} - {self.analysis.name}"


PERMISSION_CHOICES = [
    ("create", "Create"),
    ("view", "View"),
    ("update", "Update"),
    ("delete", "Delete"),
]


class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    users = models.ManyToManyField(User, related_name="roles", blank=True)

    def __str__(self):
        return self.name


class Permission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="permissions")
    module = models.CharField(max_length=200)  # dynamic module name
    action = models.CharField(max_length=10, choices=PERMISSION_CHOICES)

    class Meta:
        unique_together = ("role", "module", "action")

    def __str__(self):
        return f"{self.role.name} - {self.module} - {self.action}"
    

class ComponentResult(models.Model):
    entry = models.ForeignKey(DynamicFormEntry, related_name="results", on_delete=models.CASCADE)
    component = models.ForeignKey(Component, related_name="results", on_delete=models.CASCADE)
    value = models.TextField(null=True, blank=True)
    numeric_value = models.FloatField(null=True, blank=True)
    remarks = models.TextField(null=True, blank=True)

    authorization_flag = models.BooleanField(default=False)
    authorization_remark = models.TextField(null=True, blank=True)

    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)



class SystemConfiguration(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.CharField(max_length=255, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.key} = {self.value}"

    

    