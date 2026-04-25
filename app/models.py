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
import phonenumbers
from django.core.exceptions import ValidationError
from django.db.models import Sum
from datetime import timedelta


class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        abstract = True
        ordering = ["-id"]



class User(AbstractUser, BaseModel):
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    email = models.EmailField(_("Email"), unique=True, null=False, blank=False)
    password = models.CharField(max_length=128, null=False, blank=False)
    name = models.CharField(_("Full Name"), max_length=255, null=False, blank=False)

    idle_time = models.PositiveIntegerField(default=15, help_text="Auto logout time in minutes after inactivity")
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
    last_activity = models.DateTimeField(null=True, blank=True)
    signature = models.ImageField(upload_to="signatures/", null=True, blank=True)
    
    

    def clean(self):
        super().clean()
        # ✅ DOB validation
        if self.dob and self.dob > timezone.now().date():
            raise ValidationError({"dob": "Date of Birth cannot be in the future."})

        # ✅ Phone number validation
        if self.phone_number:
            try:
                parsed = phonenumbers.parse(self.phone_number, None)  # None = allow any country code
                if not phonenumbers.is_valid_number(parsed):
                    raise ValidationError({"phone_number": "Enter a valid international phone number (e.g. +14155552671)."})
            except phonenumbers.NumberParseException:
                raise ValidationError({"phone_number": "Invalid phone number format. Use international format like +14155552671."})


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


MAIN_PREPARATION_CHOICES = [
    ('MPA', 'Phase A'),
    ('MPB', 'Phase B'),
    ('MPC', 'Phase C'),
    ('MPS', 'Solvent and Solution'),  
]

# Sub-types for Solvent/Solution
SOLVENT_SUB_CHOICES = [
    ('NSS', 'Nicotine Standard Solution'),
    ('PSS', 'Solvent Solution'),
]

# Nicotine Standard Types
NICOTINE_STANDARD_CHOICES = [
    ('NSA', 'Nicotine Standard A'),
    ('NSB', 'Nicotine Standard B'),
]

def generate_preparation_id(prep_type):
    """
    Generate unique preparation ID with syntax:
    MPA-DDYYMM-XXXXX for Phase A
    MPB-DDYYMM-XXXXX for Phase B
    MPC-DDYYMM-XXXXX for Phase C
    NSS-DDYYMM-XXXXX for Nicotine Standard Solution
    PSS-DDYYMM-XXXXX for Solvent Solution
    """
    now = timezone.now()
    number = str(uuid.uuid4().int)[:5]  # 5-digit unique number
    return f"{prep_type}-{now.strftime('%d%m%y')}-{number}"


class Preparation(models.Model):
    prep_id = models.CharField(max_length=50, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    prepared_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    details = models.TextField(blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.prep_id:
            self.prep_id = generate_preparation_id("MP") 
        super().save(*args, **kwargs)

    def __str__(self):
        return self.prep_id

class NicotineAssayReport(models.Model):
    preparation = models.ForeignKey(
        Preparation,
        on_delete=models.CASCADE,
        related_name="reports", null=True, blank=True
    )

    prep_type = models.CharField(max_length=3, choices=MAIN_PREPARATION_CHOICES)
    prep_sub_type = models.CharField(max_length=3, choices=SOLVENT_SUB_CHOICES, blank=True, null=True)
    prep_id = models.CharField(max_length=50, unique=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    expiry_days = models.PositiveIntegerField()
    expiry_date = models.DateField(blank=True, null=True)

    # Phase A & B
    volume_prepared = models.FloatField(blank=True, null=True)
    ammonium_acetate_weight = models.FloatField(blank=True, null=True)
    pH_reading = models.FloatField(blank=True, null=True)

    # Solvent / Solution
    water_weight = models.FloatField(blank=True, null=True)
    methanol_weight = models.FloatField(blank=True, null=True)

    # Nicotine Standard
    nicotine_standard_type = models.CharField(
        max_length=3,
        choices=NICOTINE_STANDARD_CHOICES,
        blank=True,
        null=True
    )

    def save(self, *args, **kwargs):

        if self.preparation:
            existing_report = NicotineAssayReport.objects.filter(
                preparation=self.preparation
            ).exclude(id=self.id).first()

            if existing_report:
                if existing_report.prep_type != self.prep_type:
                    raise ValidationError(
                        f"All nicotine entries for this preparation must be of type '{existing_report.prep_type}'"
                    )

        # 🔽 Existing logic (same as yours)
        if self.preparation:
            NicotineAssayReport.objects.filter(
                preparation=self.preparation,
                expiry_date__gte=timezone.now().date()
            ).exclude(id=self.id).update(
                expiry_date=timezone.now().date() - timedelta(days=1)
            )

        if not self.prep_id:
            if self.prep_type == 'MPS' and self.prep_sub_type:
                prefix = self.prep_sub_type
            elif self.nicotine_standard_type:
                prefix = self.nicotine_standard_type
            else:
                prefix = self.prep_type

            self.prep_id = generate_preparation_id(prefix)

        if self.expiry_days and not self.expiry_date:
            self.expiry_date = timezone.now().date() + timedelta(days=self.expiry_days)

        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        return self.expiry_date and self.expiry_date < timezone.now().date()

    def __str__(self):
        return self.prep_id

class Training(BaseModel):
    training_id = models.CharField(max_length=100, unique=True, editable=False)
    description = models.TextField()

    attachment = models.URLField(null=True, blank=True) 

    MODE_CHOICES = (
        ("online", "Online"),
        ("onsite", "Onsite"),
    )
    mode = models.CharField(max_length=10, choices=MODE_CHOICES)

    users = models.ManyToManyField(
        User,
        through="UserTraining",
        related_name="trainings",
        blank=True
    )

    def save(self, *args, **kwargs):
        if not self.training_id:
            last = Training.objects.order_by("-id").first()
            if last and last.training_id:
                last_num = int(last.training_id.replace("T", ""))
                new_id = f"T{str(last_num + 1).zfill(3)}"
            else:
                new_id = "T001"

            self.training_id = new_id

        super().save(*args, **kwargs)

    def __str__(self):
        return self.training_id
    
    
class UserTraining(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    training = models.ForeignKey(Training, on_delete=models.CASCADE)

    training_date = models.DateField()
    expiry_date = models.DateField()

    def __str__(self):
        return f"{self.user.username} - {self.training.training_id}"


class Analysis(BaseModel):
    name = models.CharField(max_length=255)
    alias_name = models.CharField(max_length=255, null=True, blank=True)
    version = models.PositiveIntegerField(default=1, null=True, blank=True)

    user_groups = models.ManyToManyField(UserGroup, null=True, blank=True)
    type =  models.CharField(max_length=255, null=True, blank=True)
    test_method = models.ForeignKey(TestMethod, on_delete=models.SET_NULL, null=True, blank=True)
    price = models.FloatField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    prep = models.ManyToManyField(
        "Preparation",
        related_name="analyses",
        blank=True
    )
    trainings = models.ManyToManyField(
        Training,
        related_name="analyses",
        blank=True,
        null=True,
    )
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
    analysis = models.ForeignKey(Analysis, related_name='components', on_delete=models.CASCADE,null=True,blank=True)
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
    default_result = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Default result value that appears in result entry screen"
    )
    listname = models.ForeignKey(List, on_delete=models.SET_NULL, null=True, blank=True, related_name="components")

    custom_function = models.ForeignKey('CustomFunction',on_delete=models.SET_NULL,null=True,blank=True,related_name='components')

    def __str__(self):
        return f"{self.name}"



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
    

from django.db.models import Max

class InstrumentHistory(BaseModel):
    instrument = models.ForeignKey(Instrument, on_delete=models.CASCADE, related_name='history')
    action_type = models.CharField(max_length=100, choices=choices.ActionType.choices)
    start_date = models.DateField()

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        instrument = self.instrument

        # -----------------------------
        # Latest Calibration History
        # -----------------------------
        latest_calibration = InstrumentHistory.objects.filter(
            instrument=instrument,
            action_type="Calibration",
            is_deleted=False
        ).order_by("-start_date").first()

        if latest_calibration and instrument.calibration_period:
            instrument.next_calibration_date = (
                latest_calibration.start_date + timedelta(days=instrument.calibration_period)
            )

        # -----------------------------
        # Latest Prevention History
        # -----------------------------
        latest_prevention = InstrumentHistory.objects.filter(
            instrument=instrument,
            action_type="Prevention",
            is_deleted=False
        ).order_by("-start_date").first()

        if latest_prevention and instrument.prevention_period:
            instrument.next_prevention_date = (
                latest_prevention.start_date + timedelta(days=instrument.prevention_period)
            )

        instrument.save(update_fields=[
            "next_calibration_date",
            "next_prevention_date"
        ])

    def __str__(self):
        return f"{self.instrument.name} - {self.action_type} on {self.start_date}"
    
class Inventory(BaseModel):
    name = models.CharField(max_length=255)
    type =  models.CharField(max_length=255, null=True, blank=True)
    user_groups = models.ManyToManyField(UserGroup, blank=True, null=True)
    location = models.CharField(max_length=255)
    unit = models.ForeignKey('Unit', on_delete=models.SET_NULL, null=True)
    total_quantity = models.IntegerField(default=0)
    description = models.TextField(blank=True, null=True)
    supplier_name = models.CharField(max_length=255, null=True, blank=True)
    batch_no = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.name


class Stock(BaseModel):
    inventory = models.ForeignKey(Inventory, on_delete=models.CASCADE, related_name='stocks')
    stock_date = models.DateField(blank=True, null=True)
    expiration_date = models.DateField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    quantity = models.IntegerField()
    batch_no = models.CharField(max_length=255, null=True, blank=True) 

    def __str__(self):
        return f"{self.inventory.name} - {self.quantity}"



class StockConsumption(BaseModel):
    stock = models.ForeignKey(
        Stock, 
        on_delete=models.CASCADE, 
        related_name="consumptions"
    )
    consumed_quantity = models.IntegerField()
    notes = models.TextField(blank=True, null=True)
    consumed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    def __str__(self):
        return f"{self.stock.inventory.name} consumed {self.consumed_quantity}"

    def save(self, *args, **kwargs):
        if self.consumed_quantity > self.stock.quantity:
            raise ValueError("Not enough stock to consume")

        # ❌ REMOVE THIS LINE
        # self.stock.quantity -= self.consumed_quantity
        # self.stock.save()

        super().save(*args, **kwargs)

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
        ('date', 'Date'),
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
    entry = models.ForeignKey("DynamicFormEntry", on_delete=models.CASCADE, null=True, blank=True)
    analysis = models.ForeignKey("Analysis", on_delete=models.CASCADE)
    components = models.ManyToManyField("Component", blank=True)

    def __str__(self):
        return f"{self.entry.id} - {self.analysis.name}"


class DynamicFormEntry(BaseModel):
    STATUS_CHOICES = [
        ("initiated", "Initiated"),
        ("received", "Received"),
        ("in_progress", "In Progress"), 
        ("completed", "Completed"),
        ("assign_analyst", "Assign Analyst"), 
        ("hold", "Hold"),
        ("unhold", "Un Hold"),
        ("release", "Realease"),
        ("rejected", "Rejected"),
        ("cancelled", "Cancelled"),
        ("reactivate", "Reactivate"),]

    form = models.ForeignKey(SampleForm, on_delete=models.CASCADE)
    data = models.JSONField()
    sample_text_id = models.CharField(
        max_length=50, blank=True, db_index=True
    )

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="initiated")  # ✅ add this

    analyst = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="analyzed_samples"
    )
    logged_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="logged_samples"
    )
    comment = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    analyses = models.ManyToManyField("Analysis", through="DynamicFormEntryAnalysis", related_name="entries", blank=True)
    user_groups = models.ManyToManyField("UserGroup", blank=True, related_name="sample_entries")
    retaining_sample_location = models.TextField(null=True, blank=True)
    is_followup = models.BooleanField(default=False)
    parent_sample = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="followup_samples"
    )


    def save(self, *args, **kwargs):
        is_new = self.pk is None
        super().save(*args, **kwargs)

        # -------------------------
        # Set sample_text_id if new
        # -------------------------
        if is_new and not self.sample_text_id:
            created_date_str = self.created_at.strftime("%Y%m%d")
            if self.is_followup and self.parent_sample:
                # Include parent sample ID in the text ID
                self.sample_text_id = f"S-{created_date_str}-{self.id}-F{self.parent_sample.id}"
            else:
                self.sample_text_id = f"S-{created_date_str}-{self.id}"
            super().save(update_fields=["sample_text_id"])

        # -------------------------
        # Assign user_groups from the associated SampleForm
        # -------------------------
        if is_new and self.form:
            form_user_groups = self.form.user_groups.all()
            if form_user_groups.exists():
                self.user_groups.set(form_user_groups)

    def __str__(self):
        return f"Entry {self.id} - {self.form.sample_name} ({self.status})"


def attachment_upload_path(instance, filename):
    return f"uploads/sample/{filename}"


class DynamicFormAttachment(models.Model):
    entry = models.ForeignKey(
        "DynamicFormEntry",
        on_delete=models.CASCADE,
        related_name="attachments", null=True,  blank=True
    )
    field = models.ForeignKey("SampleField", on_delete=models.CASCADE, blank=True, null=True)
    file = models.FileField(upload_to=attachment_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.field.field_name} - {self.file.name}"


from django.db import models
from django.utils import timezone


class StatusHistory(models.Model):
    entry = models.ForeignKey("DynamicFormEntry", on_delete=models.CASCADE, related_name="status_history")
    old_status = models.CharField(max_length=20, null=True, blank=True)
    new_status = models.CharField(max_length=20)
    updated_by = models.ForeignKey("User", on_delete=models.SET_NULL, null=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True, null=True)
    tat = models.FloatField(null=True, blank=True, help_text="TAT in seconds")

    def save(self, *args, **kwargs):
        # Track if this is a new record
        is_new = self.pk is None

        # First save to get updated_at set
        super().save(*args, **kwargs)

        # Only calculate TAT for new records
        if is_new:
            # Get the last previous status for the same entry
            last_status = StatusHistory.objects.filter(entry=self.entry).exclude(pk=self.pk).order_by('-updated_at').first()
            if last_status:
                delta = self.updated_at - last_status.updated_at
                self.tat = delta.total_seconds()  # store seconds
                super().save(update_fields=["tat"])
            else:
                # First status record → no previous TAT
                self.tat = 0
                super().save(update_fields=["tat"])


class SampleComponent(models.Model):
    entry_analysis = models.ForeignKey(
        "DynamicFormEntryAnalysis",
        on_delete=models.CASCADE,
        related_name="sample_components",null=True,blank=True
    )

    component = models.ForeignKey(
        "Component",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sample_overrides"
    )

    # ===== OVERRIDABLE FIELDS =====
    type = models.CharField(max_length=50, choices=choices.ComponentTypes.choices, null=True, blank=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    unit = models.ForeignKey("Unit", on_delete=models.SET_NULL, null=True, blank=True)

    minimum = models.FloatField(null=True, blank=True)
    maximum = models.FloatField(null=True, blank=True)
    decimal_places = models.IntegerField(null=True, blank=True)
    rounding = models.IntegerField(null=True, blank=True)

    spec_limits = models.JSONField(blank=True, null=True)
    description = models.TextField(null=True, blank=True)
    optional = models.BooleanField(null=True)

    calculated = models.BooleanField(default=False)
    custom_function = models.ForeignKey(
        "CustomFunction",
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    default_result = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Default result value that appears in result entry screen"
    )

    def __str__(self):
        return f"{self.name or self.component.name} (Sample Component)"


class SampleComponentFunctionParameter(models.Model):
    sample_component = models.ForeignKey(
        SampleComponent,
        on_delete=models.CASCADE,
        related_name="function_parameters"
    )
    parameter = models.CharField(max_length=255)
    mapped_sample_component = models.ForeignKey(
        SampleComponent,
        on_delete=models.CASCADE,
        related_name="used_in_calculations"
    )


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
    sample_form = models.ManyToManyField(SampleForm, related_name="request_forms")
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
        ("release", "Realease"),
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
    comment = models.TextField(null=True, blank=True)


class DynamicRequestAttachment(models.Model):
    entry = models.ForeignKey("DynamicRequestEntry", on_delete=models.CASCADE, related_name="attachments", null=True,  blank=True)
    field = models.ForeignKey("RequestField", on_delete=models.CASCADE, blank=True, null=True)
    file = models.FileField(upload_to="uploads/request/")

    def __str__(self):
        return f"{self.field.field_name} - {self.file.name}"



class Product(BaseModel):

    PRODUCT_TYPE_CHOICES = [
        ("FINISHED_GOODS", "Finished Goods"),
        ("BLEND", "Blend"),
        ("RAW_MATERIALS", "Raw Materials"),
        ("PACKAGING_MATERIALS", "Packaging Materials"),
        ("FLAVOUR_MATERIALS", "Flavour Materials"),
    ]
    name = models.CharField(max_length=255)
    version = models.PositiveIntegerField(default=1)
    description = models.TextField(blank=True)

    product_type = models.CharField(
        max_length=20,
        choices=PRODUCT_TYPE_CHOICES,
        default="FG_SAMPLE"
    )


    user_groups = models.ManyToManyField(
        UserGroup,
        blank=True,
        related_name="products"
    )
    def __str__(self):
        return self.name


class SamplingPoint(BaseModel):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class Grade(BaseModel):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class ProductSamplingGrade(BaseModel):
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name="sampling_grades"
    )
    sampling_point = models.ForeignKey(
        SamplingPoint,
        on_delete=models.CASCADE,
        null=True, 
        blank=True
    )
    grade = models.ForeignKey(
        Grade,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    class Meta:
        unique_together = ("product", "sampling_point", "grade")

    def __str__(self):
        return f"{self.product} | {self.sampling_point} | {self.grade}"


class ProductSamplingGradeAnalysis(BaseModel):
    product_sampling_grade = models.ForeignKey(
        ProductSamplingGrade,
        on_delete=models.CASCADE,
        related_name="analyses"
    )
    analysis = models.ForeignKey(
        Analysis,
        on_delete=models.CASCADE
    )

    sample_components = models.ManyToManyField(
        SampleComponent,
        blank=True,
        related_name="product_sampling_grade_analyses"
    )

    class Meta:
        unique_together = ("product_sampling_grade", "analysis")

    def __str__(self):
        return f"{self.product_sampling_grade} → {self.analysis}"

# class ProductAnalysis(BaseModel):
#     product = models.ForeignKey(Product, on_delete=models.CASCADE)
#     analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE)
#     sample_components = models.ManyToManyField(
#         "SampleComponent", blank=True
#     )


#     def __str__(self):
#         return f"{self.product.name} - {self.analysis.name}"


PERMISSION_CHOICES = [
    ("create", "Create"),
    ("view", "View"),
    ("update", "Update"),
    ("delete", "Delete"),
    ("receive", "Receive"),
    ("result_entry", "Result Entry"),
    ("release", "Realease"),
    ("cancel_restore", "Cancel/Restore"),
    ("reactivate", "Reactivate"),
    ("consume_stock", "Consume Stock"),
]

class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    users = models.ManyToManyField(User, related_name="roles", blank=True)

    def __str__(self):
        return self.name


class Permission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="permissions")
    module = models.CharField(max_length=200)  # dynamic module name
    action = models.CharField(max_length=100, choices=PERMISSION_CHOICES)

    class Meta:
        unique_together = ("role", "module", "action")

    def __str__(self):
        return f"{self.role.name} - {self.module} - {self.action}"
    

class ComponentResult(models.Model):
    entry = models.ForeignKey(DynamicFormEntry, related_name="results", on_delete=models.CASCADE)
    sample_component = models.ForeignKey(SampleComponent, related_name="results", on_delete=models.CASCADE)
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

    
class Activity(BaseModel):
    ACTION_CHOICES = [
        ("create", "Created"),
        ("update", "Updated"),
        ("delete", "Deleted"),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="activities",
    )
    model_name = models.CharField(max_length=100)
    object_id = models.CharField(max_length=100, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    description = models.TextField(blank=True, null=True)
    changes = models.JSONField(null=True, blank=True) 

    def __str__(self):
        return f"{self.user} {self.action} {self.model_name}"



class ReportTemplate(models.Model):
    name = models.CharField(max_length=255)
    html_content = models.TextField()   # Raw HTML (with {{ placeholders }})
    css_content = models.TextField(blank=True, null=True)
    fields = models.JSONField(default=list)    # e.g. [{"label": "Customer", "path": "form.sample_name"}, {"label": "Analyst", "path": "analyst.name"}]
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class QueryReportTemplate(BaseModel):
    name = models.CharField(max_length=255)
    raw_html_content = models.TextField()
    jinja_html_content = models.TextField(blank=True, null=True)
    css_content = models.TextField(blank=True, null=True)
    fields = models.JSONField(default=list) 

    # Added fields ↓
    sql_query = models.TextField(blank=True, null=True)  # e.g. SELECT * FROM ...
    parameters = models.JSONField(default=dict, blank=True, null=True)  # {"sample_id": "int"}
    output_format = models.CharField(
        max_length=10,
        default='pdf',
        choices=(('pdf', 'PDF'), ('html', 'HTML')),
    )

    def __str__(self):
        return self.name

from django.db import transaction
class GeneratedReport(models.Model):
    id = models.CharField(primary_key=True, max_length=30, editable=False)

    sample = models.ForeignKey('DynamicFormEntry', on_delete=models.CASCADE, related_name='generated_reports')
    template = models.ForeignKey('QueryReportTemplate', on_delete=models.CASCADE, related_name='generated_reports')
    pdf_url = models.URLField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            with transaction.atomic():
                today = timezone.now().strftime("%Y%m%d")

                last_report = (
                    GeneratedReport.objects
                    .select_for_update()
                    .filter(id__startswith=f"R-{today}-")
                    .order_by('-created_at')
                    .first()
                )

                if last_report:
                    last_number = int(last_report.id.split("-")[-1])
                    new_number = last_number + 1
                else:
                    new_number = 1

                self.id = f"R-{today}-{new_number}"

                super().save(*args, **kwargs)
        else:
            super().save(*args, **kwargs)

    def __str__(self):
        return self.id
    

class Investigation(models.Model):
    sample = models.ForeignKey(DynamicFormEntry, on_delete=models.CASCADE, related_name="investigations")
    rejected_at = models.DateTimeField(default=timezone.now)
    rejection_reason = models.TextField()
    corrective_actions = models.TextField(blank=True, null=True)
    preventive_actions = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Investigation for Sample {self.sample.id}"




import random
from django.utils import timezone

def generate_inspection_id():
    now = timezone.now().strftime('%Y%m%d%H%M%S')
    random_digits = str(random.randint(10000, 99999))
    return f"IMS-{now}-{random_digits}"

class IncomingMaterialSampleInspection(models.Model):
    CLARITY_CHOICES = [
        ('clear', 'Clear'),
        ('not_clear', 'Not Clear'),
    ]

    PRESENCE_CHOICES = [
        ('present', 'Present'),
        ('absent', 'Absent'),
    ]
    DECISION_CHOICES = [
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('partial', 'Partially Accepted'),
    ]

    inspection_sheet_no = models.CharField(
        max_length=50,
        primary_key=True,
        default=generate_inspection_id,
        editable=False
    )
    material = models.ForeignKey(
        Product,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='inspections'
    )
    grn_number = models.CharField(max_length=100, blank=True, null=True)
    received_total_number = models.PositiveIntegerField(blank=True, null=True)
    vendor_lot_number = models.CharField(max_length=100, blank=True, null=True)

    # A - Suppliers Label Information
    clarity = models.CharField(
        max_length=20,
        choices=CLARITY_CHOICES,
        blank=True,
        null=True
    )

    item_description = models.CharField(
        max_length=20,
        choices=PRESENCE_CHOICES,
        blank=True,
        null=True
    )

    supplier_name = models.CharField(
        max_length=20,
        choices=PRESENCE_CHOICES,
        blank=True,
        null=True
    )

    supplier_lot_number = models.CharField(
        max_length=20,
        choices=PRESENCE_CHOICES,
        blank=True,
        null=True
    )

    manufacturing_date = models.CharField(
        max_length=20,
        choices=PRESENCE_CHOICES,
        blank=True,
        null=True
    )

    expiry_date = models.CharField(
        max_length=20,
        choices=PRESENCE_CHOICES,
        blank=True,
        null=True
    )

    # B - Sampling Information
    number_of_containers_to_be_opened = models.PositiveIntegerField(blank=True, null=True)
    sampled_quantity = models.CharField(max_length=255, blank=True, null=True)
    sampled_by = models.CharField(max_length=255, blank=True, null=True)

    container_sealed_after_sampling = models.BooleanField(default=False)
    container_labeled_after_sealed = models.BooleanField(default=False)

    checked_by = models.CharField(max_length=255, blank=True, null=True)
    checked_sign_date = models.DateField(blank=True, null=True)

    approved_by = models.CharField(max_length=255, blank=True, null=True)
    approved_sign_date = models.DateField(blank=True, null=True)

    decision = models.CharField(
        max_length=20,
        choices=DECISION_CHOICES,
        null=True,
        blank=True
    )

    accepted_quantity = models.PositiveIntegerField(null=True, blank=True)


    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'incoming_material_sample_inspection'
        ordering = ['-created_at']

    def __str__(self):
        return self.inspection_sheet_no

    