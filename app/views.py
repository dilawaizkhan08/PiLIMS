import uuid
import random
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils import timezone
from django.conf import settings
from .permissions import *
from rest_framework.exceptions import PermissionDenied
from rest_framework import status, views, generics, viewsets
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.views import APIView
from rest_framework.decorators import action
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter
from django.contrib.auth.models import update_last_login
from rest_framework.parsers import MultiPartParser, FormParser

from django.contrib.auth import authenticate
from .models import User
from .serializers import *

import ast
from rest_framework import serializers, viewsets
from rest_framework.decorators import action

from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from datetime import datetime
from . import models
from .serializers import build_dynamic_request_serializer, build_dynamic_serializer

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.apps import apps
from django.core.serializers import serialize
import json
from datetime import datetime, date
import inflection
from rest_framework import viewsets, mixins
from django.db.models import F
from django.apps import apps
from app.mixins import TrackUserMixin


def get_config(key, default=None):
    from .models import SystemConfiguration
    config = SystemConfiguration.objects.filter(key=key).first()
    return config.value if config else default

class RegisterView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Generate auth token
            token, _ = Token.objects.get_or_create(user=user)
            user_data = UserSerializer(user, context={'request': request}).data

            return Response({
                "message": "User registered successfully.",
                "token": token.key,
                "user": user_data,
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

            # 🔑 yahan se config table se value uthayega
            max_attempts = int(get_config("max_wrong_password_attempts", 5))

            if not user.is_active:
                return Response({"error": "Your account is deactivated. Please contact admin."}, status=status.HTTP_403_FORBIDDEN)

            user_auth = authenticate(request, email=email, password=password)

            if user_auth:
                user.failed_login_attempts = 0
                user.save(update_fields=["failed_login_attempts"])
                token, _ = Token.objects.get_or_create(user=user)
                update_last_login(None, user)

                user_data = UserSerializer(user, context={'request': request}).data
                return Response({"token": token.key, "user": user_data}, status=status.HTTP_200_OK)

            # ❌ Wrong password case
            user.failed_login_attempts = F("failed_login_attempts") + 1
            user.save(update_fields=["failed_login_attempts"])
            user.refresh_from_db()

            if user.failed_login_attempts >= max_attempts:
                user.is_active = False
                user.save(update_fields=["is_active"])
                return Response({"error": "Your account has been locked due to too many failed login attempts."}, status=status.HTTP_403_FORBIDDEN)

            remaining = max_attempts - user.failed_login_attempts
            return Response({"error": f"Invalid credentials. You have {remaining} attempts left."}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserViewSet(TrackUserMixin, viewsets.ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [SearchFilter, DjangoFilterBackend]
    search_fields = ['email', 'name']
    filterset_fields = ['is_active', 'role']

    def get_queryset(self):
        # Only return users created by the logged-in user
        return User.objects.filter(created_by=self.request.user)

    def perform_create(self, serializer):
        # Set the creator of the new user
        serializer.save(created_by=self.request.user)

    def get_object(self):
        obj = super().get_object()

        # Only allow access if the user was created by the requesting user
        if obj.created_by != self.request.user:
            raise PermissionDenied("You can only access users you have created.")
        
        return obj

    @action(detail=True, methods=["post"], url_path="toggle-activation")
    def toggle_activation(self, request, pk=None):
        user = self.get_object()
        user.is_active = not user.is_active
        user.save()

        return Response({
            "message": f"User {'activated' if user.is_active else 'deactivated'} successfully.",
            "user": self.get_serializer(user).data
        }, status=status.HTTP_200_OK)
    

    @action(detail=False, methods=["get"], url_path="stats")
    def stats(self, request):
        queryset = self.get_queryset()

        total_users = queryset.count() or 1  # division by zero avoid karne ke liye

        active_users = queryset.filter(is_active=True).count()
        inactive_users = queryset.filter(is_active=False).count()

        now = timezone.now()
        users_this_month = queryset.filter(
            created_at__month=now.month, created_at__year=now.year
        ).count()

        role_stats = queryset.values("role").annotate(count=Count("id")).order_by("-count")

        def percentage(count):
            return round((count / total_users) * 100, 2)

        data = {
            "total_users": total_users,
            "active_users": {
                "count": active_users,
                "percentage": percentage(active_users),
            },
            "inactive_users": {
                "count": inactive_users,
                "percentage": percentage(inactive_users),
            },
            "users_created_this_month": {
                "count": users_this_month,
                "percentage": percentage(users_this_month),
            },
            "users_by_role": [
                {
                    "role": r["role"],
                    "count": r["count"],
                    "percentage": percentage(r["count"]),
                }
                for r in role_stats
            ],
        }

        return Response(data, status=status.HTTP_200_OK)

class UserProfileUpdateView(generics.RetrieveUpdateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_object(self):
        return self.request.user


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = str(random.randint(1000, 9999))
            reset_session_id = str(uuid.uuid4())
            cache.set(f"otp_{otp}", {"email": email, "session": reset_session_id}, timeout=300)

            send_mail(
                "Your OTP Code for Password Reset",
                f"Your OTP code is: {otp}",
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            return Response({"detail": "OTP sent to email."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp = request.data.get("otp")
        data = cache.get(f"otp_{otp}")
        if not data:
            return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        cache.set(f"reset_session_{data['session']}", data["email"], timeout=600)
        cache.delete(f"otp_{otp}")
        return Response({"reset_session_id": data["session"]}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        reset_session_id = request.data.get("reset_session_id")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not reset_session_id or not new_password:
            return Response({"error": "Session ID and password are required."}, status=400)

        if new_password != confirm_password:
            return Response({"error": "Passwords do not match."}, status=400)

        email = cache.get(f"reset_session_{reset_session_id}")
        if not email:
            return Response({"error": "Invalid or expired session ID."}, status=400)

        try:
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            cache.delete(f"reset_session_{reset_session_id}")
            return Response({"detail": "Password reset successful."}, status=200)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=400)
        

class AnalysisAttachmentViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.AnalysisAttachment.objects.all()
    serializer_class = AnalysisAttachmentSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        files = request.FILES.getlist("files")   # multiple files expected
        analysis_id = request.data.get("analysis")

        if not files:
            return Response({"error": "No files uploaded"}, status=status.HTTP_400_BAD_REQUEST)

        attachments = []
        for file in files:
            serializer = self.get_serializer(data={"analysis": analysis_id, "file": file})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            attachments.append(serializer.data)

        return Response(attachments, status=status.HTTP_201_CREATED)



class AnalysisViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Analysis.objects.all()
    serializer_class = AnalysisSerializer
    permission_classes = [IsAuthenticated, HasModulePermission]




class CustomFunctionViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.CustomFunction.objects.all()
    serializer_class = CustomFunctionSerializer
    permission_classes = [IsAuthenticated]

    # ========= 1) VALIDATE ENDPOINT ==========
    @action(detail=False, methods=["post"], url_path="validate")
    def validate_script(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Mark as validated in session
            request.session["last_valid_function"] = request.data
            return Response({"valid": True, "message": "Function is valid"})
        return Response(serializer.errors, status=400)

    # ========= 2) OVERRIDE CREATE ==========
    def create(self, request, *args, **kwargs):
        # Just re-run validation on create
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)  # validation logic from serializer
        return super().create(request, *args, **kwargs)




class InstrumentViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Instrument.objects.all()
    serializer_class = InstrumentSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

class InstrumentHistoryViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.InstrumentHistory.objects.all()
    serializer_class = InstrumentHistorySerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class InventoryViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Inventory.objects.all()
    serializer_class = InventorySerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class StockViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Stock.objects.all()
    serializer_class = StockSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

class UnitViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Unit.objects.all()
    serializer_class = UnitSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

class CustomerViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Customer.objects.all().order_by('-created_at')
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated,HasModulePermission] 

    
    @action(detail=False, methods=["get"], url_path="stats")
    def stats(self, request):
        queryset = self.get_queryset()

        total_customers = queryset.count() or 1  # zero division avoid

        total_companies = queryset.values("company_name").distinct().count()
        with_city = queryset.exclude(city__isnull=True).exclude(city__exact="").count()
        with_description = queryset.exclude(description__isnull=True).exclude(description__exact="").count()

        def percentage(count):
            return round((count / total_customers) * 100, 2)

        data = {
            "total_customers": {
                "count": total_customers,
                "percentage": 100.0,  # total is always 100%
            },
            "total_companies": {
                "count": total_companies,
                "percentage": percentage(total_companies),
            },
            "customers_with_city": {
                "count": with_city,
                "percentage": percentage(with_city),
            },
            "customers_with_description": {
                "count": with_description,
                "percentage": percentage(with_description),
            },
        }

        return Response(data, status=status.HTTP_200_OK)

class ListViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.List.objects.all()
    serializer_class = ListSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class ValueViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Value.objects.all()
    serializer_class = ValueSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class UserGroupViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.UserGroup.objects.all()
    serializer_class = UserGroupSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class TestMethodViewSet(TrackUserMixin, viewsets.ModelViewSet):
    queryset = models.TestMethod.objects.all()
    serializer_class = TestMethodSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

    

class ComponentViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Component.objects.all()
    serializer_class = ComponentSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]





class SampleFormViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.SampleForm.objects.all()
    serializer_class = SampleFormSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

    @action(detail=False, methods=['get'])
    def property_options(self, request):
        field_property = request.query_params.get('field_property')

        if not field_property:
            return Response({"error": "field_property query parameter is required"}, status=400)

        if field_property == 'list':
            lists = models.List.objects.all().values('id', 'name')
            return Response({"type": "list", "options": list(lists)})

        elif field_property == 'link_to_table':
            tables = [model._meta.db_table for model in apps.get_models()]
            return Response({"type": "link_to_table", "options": tables})

        return Response({"type": field_property, "options": []})
    

from django.shortcuts import get_object_or_404
from datetime import datetime

class SampleFormSchemaView(APIView):
    permission_classes = [IsAuthenticated, HasModulePermission]

    def get(self, request, form_id):
        sample_form = get_object_or_404(models.SampleForm, pk=form_id)
        fields_qs = sample_form.fields.all()

        serializer_class = build_dynamic_serializer(fields_qs)
        serializer_instance = serializer_class()

        field_meta = []
        for sample_field in fields_qs:
            field_obj = serializer_instance.get_fields().get(sample_field.field_name)

            # 🔑 Map DB field_property → API type
            mapping = {
                "text": "CharField",
                "numeric": "IntegerField",
                "date_time": "DateTimeField",
                "list": "ChoiceField",
                "link_to_table": "ChoiceField",
                "attachment": "AttachmentField",  # 👈 custom type
            }

            meta = {
                "name": sample_field.field_name,
                "type": mapping.get(sample_field.field_property, field_obj.__class__.__name__),
                "required": sample_field.required,
            }

            if sample_field.list_ref:
                meta["choices"] = list(
                    sample_field.list_ref.values.values_list("value", flat=True)
                )

            field_meta.append(meta)

        return Response({
            "form_name": sample_form.sample_name,
            "fields": field_meta
        })

def convert_datetimes_to_strings(data):
    new_data = {}
    for k, v in data.items():
        if isinstance(v, datetime):
            new_data[k] = v.isoformat()
        else:
            new_data[k] = v
    return new_data


class SampleFormSubmitView(APIView):
    permission_classes = [IsAuthenticated, HasModulePermission]

    def post(self, request, form_id):
        sample_form = get_object_or_404(models.SampleForm, pk=form_id)
        serializer_class = build_dynamic_serializer(sample_form.fields.all())
        serializer = serializer_class(data=request.data)

        if serializer.is_valid():
            # ✅ Create entry first
            entry = models.DynamicFormEntry.objects.create(
                form=sample_form,
                data={},
                logged_by=request.user
            )

            clean_data = {}

            # ✅ Save form_id also in data
            clean_data["form_id"] = sample_form.id  

            for field in sample_form.fields.all():
                value = (
                    request.FILES.getlist(field.field_name)
                    if field.field_property == "attachment"
                    else serializer.validated_data.get(field.field_name)
                )

                if field.field_property == "attachment" and value:
                    file_urls = []
                    for file_obj in value:
                        attachment = models.DynamicFormAttachment.objects.create(
                            entry=entry,
                            field=field,
                            file=file_obj
                        )
                        file_urls.append(attachment.file.url)
                    clean_data[field.field_name] = file_urls

                elif isinstance(value, datetime):
                    clean_data[field.field_name] = value.isoformat()

                else:
                    clean_data[field.field_name] = value

            # ✅ handle analyses separately
            analyses = request.data.getlist("analyses")
            if analyses:
                try:
                    analysis_ids = [int(x) for x in analyses]
                    entry.analyses.set(models.Analysis.objects.filter(id__in=analysis_ids))
                    clean_data["analyses"] = analysis_ids
                except ValueError:
                    return Response(
                        {"error": "Analyses must be integers"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            entry.data = clean_data
            entry.save()

            return Response({
                "message": "Form submitted successfully",
                "form_id": sample_form.id,     # ✅ return in response
                "entry_id": entry.id,
                "data": entry.data
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DynamicSampleFormEntryViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.DynamicFormEntry.objects.all().order_by("-created_at")
    serializer_class = DynamicFormEntrySerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

     
    @action(detail=False, methods=["post"])
    def update_status(self, request):
        new_status = request.data.get("status")
        ids = request.data.get("ids", [])
        analyst_id = request.data.get("analyst_id")

        if not new_status or not ids:
            return Response({"error": "Both 'status' and 'ids' are required"}, status=400)

        entries = models.DynamicFormEntry.objects.filter(id__in=ids)

        # ✅ Handle special "assign_analyst" action
        if new_status == "assign_analyst":
            if not analyst_id:
                return Response({"error": "analyst_id is required when assigning an analyst"}, status=400)

            try:
                analyst = models.User.objects.get(id=analyst_id)
            except models.User.DoesNotExist:
                return Response({"error": f"Analyst with id {analyst_id} not found"}, status=404)

            updated_count = entries.update(analyst=analyst, status="in_progress")
            return Response({
                "message": f"Assigned analyst {analyst.id} and set status to 'in_progress' for {updated_count} entries",
                "updated_ids": ids
            })

        # ✅ Handle normal status updates
        valid_statuses = dict(models.DynamicFormEntry.STATUS_CHOICES)
        if new_status not in valid_statuses:
            return Response({"error": "Invalid status"}, status=400)

        allowed_manual = ["received", "completed", "authorized", "rejected", "cancelled", "restored"]

        for entry in entries:
            if new_status not in allowed_manual:
                return Response({"error": f"Cannot manually change status to '{new_status}'."}, status=400)
            if entry.status == "initiated" and new_status != "received":
                return Response(
                    {"error": f"Entry {entry.id} must be 'received' before other actions."}, status=400
                )

        updated_count = entries.update(status=new_status)

        return Response({
            "message": f"Status updated to '{new_status}' for {updated_count} entries",
            "updated_ids": ids
        })
    

    @action(detail=False, methods=["get"], url_path="stats")
    def get_stats(self, request):
        """Return total and status-wise counts for sample entries"""
        queryset = self.get_queryset()

        total_samples = queryset.count() or 1  # avoid division by zero

        received = queryset.filter(status="received").count()
        in_progress = queryset.filter(status="in_progress").count()
        completed = queryset.filter(status="completed").count()

        def percentage(count):
            return round((count / total_samples) * 100, 2)

        data = {
            "total_samples": {
                "count": total_samples,
                "percentage": 100.0,
            },
            "received": {
                "count": received,
                "percentage": percentage(received),
            },
            "in_progress": {
                "count": in_progress,
                "percentage": percentage(in_progress),
            },
            "completed": {
                "count": completed,
                "percentage": percentage(completed),
            },
        }

        return Response(data, status=status.HTTP_200_OK)


class DynamicRequestAttachmentViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.DynamicRequestAttachment.objects.all()
    serializer_class = DynamicRequestAttachmentSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        """
        Upload multiple files and get URLs for JSON submission.
        """
        files = request.FILES.getlist("files")  # multiple files
        entry_id = request.data.get("entry_id")  # optional
        attachments = []

        entry = None
        if entry_id:
            entry = get_object_or_404(models.DynamicRequestEntry, id=entry_id)

        for f in files:
            attachment = models.DynamicRequestAttachment.objects.create(
                entry=entry,
                field=None,  # we don’t set field yet
                file=f
            )
            attachments.append({
                "id": attachment.id,
                "url": request.build_absolute_uri(attachment.file.url)
            })

        return Response(attachments, status=status.HTTP_201_CREATED)



class DynamicFormAttachmentViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.DynamicFormAttachment.objects.all()
    serializer_class = DynamicFormAttachmentSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        """
        Upload multiple files and get URLs for JSON submission.
        """
        files = request.FILES.getlist("files")  # multiple files
        entry_id = request.data.get("entry_id")  # optional
        attachments = []

        entry = None
        if entry_id:
            entry = get_object_or_404(models.DynamicFormEntry, id=entry_id)

        for f in files:
            attachment = models.DynamicFormAttachment.objects.create(
                entry=entry,
                field=None,  # we don’t set field yet
                file=f
            )
            attachments.append({
                "id": attachment.id,
                "url": request.build_absolute_uri(attachment.file.url)
            })

        return Response(attachments, status=status.HTTP_201_CREATED)


class RequestFormViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.RequestForm.objects.all()
    serializer_class = RequestFormSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

    @action(detail=False, methods=['get'])
    def property_options(self, request):
        field_property = request.query_params.get('field_property')

        if not field_property:
            return Response({"error": "field_property query parameter is required"}, status=400)

        if field_property == 'list':
            lists = models.List.objects.all().values('id', 'name')
            return Response({"type": "list", "options": list(lists)})

        elif field_property == 'link_to_table':
            tables = [model._meta.db_table for model in apps.get_models()]
            return Response({"type": "link_to_table", "options": tables})

        return Response({"type": field_property, "options": []})


class RequestFormSchemaView(APIView):
    permission_classes = [IsAuthenticated, HasModulePermission]

    def get(self, request, form_id):
        # Get the request form
        request_form = get_object_or_404(models.RequestForm, pk=form_id)

        # ------------------ REQUEST FORM FIELDS ------------------
        req_fields_qs = request_form.fields.all()
        req_serializer_class = build_dynamic_request_serializer(req_fields_qs)
        req_serializer_instance = req_serializer_class()

        req_field_meta = []
        for req_field in req_fields_qs:
            field_obj = req_serializer_instance.get_fields().get(req_field.field_name)

            if req_field.field_property == "attachment":
                meta = {
                    "name": req_field.field_name,
                    "type": "Attachment",
                    "required": req_field.required,
                }
            else:
                meta = {
                    "name": req_field.field_name,
                    "type": field_obj.__class__.__name__ if field_obj else None,
                    "required": req_field.required,
                }

            if req_field.list_ref:
                meta["list_ref"] = req_field.list_ref.id
                meta["choices"] = list(
                    req_field.list_ref.values.values_list("value", flat=True)
                )

            req_field_meta.append(meta)

        # ------------------ ATTACHED SAMPLE FORMS ------------------
        sample_forms_meta = []
        for sample_form in request_form.sample_form.all():  # ✅ loop ManyToMany
            sample_fields_qs = sample_form.fields.all()

            sample_serializer_class = build_dynamic_serializer(sample_fields_qs)
            sample_serializer_instance = sample_serializer_class()

            sample_field_meta = []
            for sample_field in sample_fields_qs:
                field_obj = sample_serializer_instance.get_fields().get(sample_field.field_name)

                if sample_field.field_property == "attachment":
                    s_meta = {
                        "name": sample_field.field_name,
                        "type": "Attachment",
                        "required": sample_field.required,
                    }
                else:
                    s_meta = {
                        "name": sample_field.field_name,
                        "type": field_obj.__class__.__name__ if field_obj else None,
                        "required": sample_field.required,
                    }

                if sample_field.list_ref:
                    s_meta["list_ref"] = sample_field.list_ref.id
                    s_meta["choices"] = list(
                        sample_field.list_ref.values.values_list("value", flat=True)
                    )

                sample_field_meta.append(s_meta)

            sample_forms_meta.append({
                "form_name": sample_form.sample_name,
                "fields": sample_field_meta
            })

        # ------------------ RESPONSE ------------------
        return Response({
            "form_name": request_form.request_name,
            "fields": req_field_meta,
            "sample_forms": sample_forms_meta  # ✅ return list instead of single
        })


def convert_datetimes_to_strings(data):
    new_data = {}
    for k, v in data.items():
        if isinstance(v, datetime):
            new_data[k] = v.isoformat()
        else:
            new_data[k] = v
    return new_data


class RequestFormSubmitView(TrackUserMixin,APIView):
    permission_classes = [IsAuthenticated, HasModulePermission]
    parser_classes = (JSONParser,)  # only JSON needed now

    def post(self, request, form_id):
        request_form = get_object_or_404(models.RequestForm, pk=form_id)

        request_form_data = request.data.get("request_form", {})
        sample_forms_data = request.data.get("sample_forms", [])
        analyses_data = request.data.get("analyses", [])

        # validate request form
        req_serializer_class = build_dynamic_request_serializer(request_form.fields.all())
        req_serializer = req_serializer_class(data=request_form_data)
        req_serializer.is_valid(raise_exception=True)

        # create DynamicRequestEntry
        entry = models.DynamicRequestEntry.objects.create(
            request_form=request_form,
            data={},
            logged_by=request.user
        )

        # ------------------ REQUEST FORM FIELDS ------------------
        req_clean_data = {}
        for field in request_form.fields.all():
            if field.field_property == "attachment":
                urls = request_form_data.get(field.field_name, [])
                if not isinstance(urls, list):
                    urls = [urls]

                file_list = []
                for url in urls:
                    file_path = url.split('/media/')[-1]
                    attachment = models.DynamicRequestAttachment.objects.filter(
                        file__endswith=file_path
                    ).first()
                    if attachment:
                        attachment.field = field
                        attachment.entry = entry
                        attachment.save()

                        file_list.append({
                            "id": attachment.id,
                            "url": request.build_absolute_uri(attachment.file.url),
                            "path": attachment.file.path
                        })

                req_clean_data[field.field_name] = file_list

            else:
                value = req_serializer.validated_data.get(field.field_name)

                if field.field_property == "list":
                    try:
                        if isinstance(value, list):
                            ids_only = [int(v) for v in value]
                            req_clean_data[field.field_name] = ids_only
                        else:
                            req_clean_data[field.field_name] = int(value) if value is not None else None
                    except (ValueError, TypeError):
                        return Response(
                            {field.field_name: "Expected ID(s) as integer, got invalid value."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    req_clean_data[field.field_name] = (
                        value.isoformat() if isinstance(value, datetime) else value
                    )


        # ------------------ HANDLE SAMPLE FORMS ------------------
        sample_clean_list = []
        if request_form.sample_form.exists() and sample_forms_data:
            # ✅ pick first sample form (if only one linked)
            sample_form = request_form.sample_form.first()

            sample_serializer_class = build_dynamic_serializer(sample_form.fields.all())

            for sample in sample_forms_data:
                sample_serializer = sample_serializer_class(data=sample)
                sample_serializer.is_valid(raise_exception=True)

                sample_entry = models.DynamicFormEntry.objects.create(
                    form=sample_form,
                    data={},
                    logged_by=request.user
                )

                clean_sample = {}
                for field in sample_form.fields.all():
                    if field.field_property == "attachment":
                        urls = sample.get(field.field_name, [])
                        if not isinstance(urls, list):
                            urls = [urls]

                        file_list = []
                        for url in urls:
                            file_path = url.split('/media/')[-1]
                            # ✅ now use DynamicFormAttachment (not DynamicRequestAttachment)
                            attachment = models.DynamicFormAttachment.objects.create(
                                entry=sample_entry,
                                field=field,
                                file=f"uploads/sample/{file_path.split('/')[-1]}"
                            )
                            file_list.append({
                                "id": attachment.id,
                                "url": request.build_absolute_uri(attachment.file.url),
                                "path": attachment.file.path
                            })
                        clean_sample[field.field_name] = file_list

                    else:
                        value = sample_serializer.validated_data.get(field.field_name)
                        clean_sample[field.field_name] = (
                            value.isoformat() if isinstance(value, datetime) else value
                        )

                sample_entry.data = clean_sample
                sample_entry.save()
                sample_clean_list.append(clean_sample)

        # ------------------ SAVE ENTRY ------------------
        entry.data = {
            "request_form": req_clean_data,
            "sample_forms": sample_clean_list
        }
        entry.save()

        if analyses_data:
            entry.analyses.set(models.Analysis.objects.filter(id__in=analyses_data))

        serializer = DynamicRequestEntrySerializer(entry, context={"request": request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)



class DynamicRequestFormEntryViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.DynamicRequestEntry.objects.all().order_by("-created_at")
    serializer_class = DynamicRequestEntrySerializer
    permission_classes = [IsAuthenticated, HasModulePermission]

    def partial_update(self, request, pk=None):
        entry = self.get_object()

        # ---------------- Parse raw data ----------------
        request_form_data_raw = request.data.get("request_form")
        sample_forms_data_raw = request.data.get("sample_forms")

        try:
            request_form_data = (
                json.loads(request_form_data_raw)
                if isinstance(request_form_data_raw, str)
                else (request_form_data_raw or {})
            )
        except Exception:
            return Response({"error": "Invalid request_form JSON"}, status=400)

        try:
            sample_forms_data = (
                json.loads(sample_forms_data_raw)
                if isinstance(sample_forms_data_raw, str)
                else (sample_forms_data_raw or [])
            )
        except Exception:
            return Response({"error": "Invalid sample_forms JSON"}, status=400)

        # ---------------- Validate request_form ----------------
        req_serializer_class = build_dynamic_request_serializer(entry.request_form.fields.all())
        req_serializer = req_serializer_class(data=request_form_data, partial=True)
        req_serializer.is_valid(raise_exception=True)

        req_clean_data = entry.data.get("request_form", {})

        for field in entry.request_form.fields.all():
            if field.field_property == "attachment":
                # Accept both uploaded files & URLs
                new_files = request.FILES.getlist(field.field_name)
                new_urls = request_form_data.get(field.field_name, [])
                if not isinstance(new_urls, list):
                    new_urls = [new_urls] if new_urls else []

                if new_files or new_urls:
                    # Replace old
                    existing_files = models.DynamicRequestAttachment.objects.filter(entry=entry, field=field)
                    for ef in existing_files:
                        ef.file.delete(save=False)
                        ef.delete()

                    file_list = []
                    for f in new_files:
                        attachment = models.DynamicRequestAttachment.objects.create(
                            entry=entry, field=field, file=f
                        )
                        file_list.append({
                            "id": attachment.id,
                            "url": attachment.file.url,
                            "path": attachment.file.path
                        })
                    for url in new_urls:
                        file_list.append({"id": None, "url": url, "path": url})

                    req_clean_data[field.field_name] = file_list
                else:
                    # Keep existing
                    existing_files = models.DynamicRequestAttachment.objects.filter(entry=entry, field=field)
                    req_clean_data[field.field_name] = [
                        {"id": f.id, "url": f.file.url, "path": f.file.path} for f in existing_files
                    ]
            else:
                value = req_serializer.validated_data.get(field.field_name, req_clean_data.get(field.field_name))
                req_clean_data[field.field_name] = (
                    value.isoformat() if isinstance(value, datetime) else value
                )

        # ---------------- Update sample forms ----------------
        sample_entry_list = []
        sample_forms = entry.request_form.sample_form.all()

        if sample_forms and sample_forms_data:
            for i, (sample_form, sample_data) in enumerate(zip(sample_forms, sample_forms_data)):
                # validate with dynamic serializer
                sample_serializer_class = build_dynamic_request_serializer(sample_form.fields.all())
                sample_serializer = sample_serializer_class(data=sample_data, partial=True)
                sample_serializer.is_valid(raise_exception=True)

                sample_id = sample_data.get("id")
                sample_entry = (
                    models.DynamicFormEntry.objects.filter(id=sample_id).first()
                    if sample_id else None
                )
                if not sample_entry:
                    sample_entry = models.DynamicFormEntry.objects.create(
                        form=sample_form, data={}, logged_by=request.user
                    )

                clean_sample = {}
                for field in sample_form.fields.all():
                    if field.field_property == "attachment":
                        file_key = f"sample_forms[{i}][{field.field_name}]"
                        new_files = request.FILES.getlist(file_key)
                        new_urls = sample_data.get(field.field_name, [])
                        if not isinstance(new_urls, list):
                            new_urls = [new_urls] if new_urls else []

                        if new_files or new_urls:
                            existing_files = models.DynamicFormAttachment.objects.filter(entry=sample_entry, field=field)
                            for ef in existing_files:
                                ef.file.delete(save=False)
                                ef.delete()

                            file_list = []
                            for f in new_files:
                                attachment = models.DynamicFormAttachment.objects.create(
                                    entry=sample_entry, field=field, file=f
                                )
                                file_list.append({
                                    "id": attachment.id,
                                    "url": attachment.file.url,
                                    "path": attachment.file.path
                                })
                            for url in new_urls:
                                file_list.append({"id": None, "url": url, "path": url})

                            clean_sample[field.field_name] = file_list
                        else:
                            existing_files = models.DynamicFormAttachment.objects.filter(entry=sample_entry, field=field)
                            clean_sample[field.field_name] = [
                                {"id": f.id, "url": f.file.url, "path": f.file.path} for f in existing_files
                            ]
                    else:
                        value = sample_serializer.validated_data.get(
                            field.field_name, sample_entry.data.get(field.field_name)
                        )
                        clean_sample[field.field_name] = (
                            value.isoformat() if isinstance(value, datetime) else value
                        )

                sample_entry.data = clean_sample
                sample_entry.save()
                sample_entry_list.append(sample_entry)

        # ---------------- Save entry ----------------
        entry.data = {
            "request_form": req_clean_data,
            "sample_forms": [{"id": e.id} for e in sample_entry_list]
        }
        entry.save()

        return Response(DynamicRequestEntrySerializer(entry, context={"request": request}).data)

    @action(detail=False, methods=["post"])
    def update_status(self, request):
        new_status = request.data.get("status")
        ids = request.data.get("ids", [])

        # ✅ Validate request
        if not new_status or not ids:
            return Response(
                {"error": "Both 'status' and 'ids' are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ✅ Validate status value
        valid_statuses = dict(models.DynamicRequestEntry.STATUS_CHOICES)
        if new_status not in valid_statuses:
            return Response(
                {"error": f"Invalid status '{new_status}'"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ✅ Allowed manual transitions only
        allowed_manual = ["received", "authorized", "rejected", "cancelled", "restored"]
        if new_status not in allowed_manual:
            return Response(
                {"error": f"Cannot manually change status to '{new_status}'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ✅ Fetch matching entries
        entries = models.DynamicRequestEntry.objects.filter(id__in=ids)

        # ✅ Validate transition rules
        for entry in entries:
            if entry.status == "initiated" and new_status != "received":
                return Response(
                    {"error": f"Request {entry.id} must be 'received' before other actions."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # ✅ Perform bulk update
        updated_count = entries.update(status=new_status)

        return Response(
            {
                "message": f"Status updated to '{new_status}' for {updated_count} request(s)",
                "updated_ids": ids,
            },
            status=status.HTTP_200_OK,
        )
    
        
    @action(detail=False, methods=["get"], url_path="stats")
    def get_stats(self, request):
        """Return total and status-wise counts"""
        queryset = self.get_queryset()

        total_requests = queryset.count() or 1  # avoid division by zero

        initiated = queryset.filter(status="initiated").count()
        received = queryset.filter(status="received").count()
        authorized = queryset.filter(status="authorized").count()

        def percentage(count):
            return round((count / total_requests) * 100, 2)

        data = {
            "total_requests": {
                "count": total_requests,
                "percentage": 100.0,
            },
            "initiated": {
                "count": initiated,
                "percentage": percentage(initiated),
            },
            "received": {
                "count": received,
                "percentage": percentage(received),
            },
            "authorized": {
                "count": authorized,
                "percentage": percentage(authorized),
            },
        }

        return Response(data, status=status.HTTP_200_OK)

class ProductViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    


class RoleViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Role.objects.all()
    serializer_class = RoleSerializer


class ModuleViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
    Read-only endpoint to list all DB tables (modules) with CRUD actions
    """
    def list(self, request, *args, **kwargs):
        modules = []
        for model in apps.get_models():
            modules.append({
                "module": model._meta.db_table,
                "actions": ["create", "view", "update", "delete"]
            })
        return Response(modules)


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


class DynamicTableDataView(APIView):
    """
    POST request:
    {
        "table_name": "app_analysis",
        "fields": ["name", "user_groups", "test_method"],  # optional
        "computed_fields": {                               # optional
            "total_value": {
                "type": "sum",
                "fields": ["price", "version"]
            },
            "name_with_version": {
                "type": "concat",
                "fields": ["name", "version"]
            }
        }
    }
    Response: requested table data with applied filters and computed fields.
    """
    permission_classes = [IsAuthenticated, HasModulePermission]

    def post(self, request, *args, **kwargs):
        table_name = request.data.get("table_name")
        requested_fields = request.data.get("fields", None)  # optional
        computed_fields = request.data.get("computed_fields", {})  # optional

        if not table_name:
            return Response({"error": "table_name is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            if "_" in table_name:
                app_label, model_snake = table_name.split("_", 1)
                model_name = inflection.camelize(model_snake)
            else:
                return Response({"error": f"Invalid table_name format: {table_name}"}, status=status.HTTP_400_BAD_REQUEST)

            model = apps.get_model(app_label, model_name)
            if not model:
                return Response({"error": f"Model '{model_name}' not found in app '{app_label}'"}, status=status.HTTP_404_NOT_FOUND)
        except LookupError:
            return Response({"error": f"Model '{table_name}' not found"}, status=status.HTTP_404_NOT_FOUND)

        # Fetch all objects
        objects = model.objects.all()
        data = []

        for obj in objects:
            row = {}

            # Decide which fields to include
            all_field_names = [f.name for f in model._meta.get_fields() if not f.auto_created or f.concrete]
            fields_to_use = requested_fields or all_field_names

            for field_name in fields_to_use:
                try:
                    field = model._meta.get_field(field_name)
                    value = getattr(obj, field_name)

                    # Handle ManyToMany
                    if field.many_to_many:
                        value = [r.name if hasattr(r, "name") else str(r) for r in value.all()]
                    # Handle ForeignKey / OneToOne
                    elif field.one_to_one or field.many_to_one:
                        value = value.name if value and hasattr(value, "name") else (str(value) if value else None)

                    row[field_name] = value
                except Exception:
                    row[field_name] = None

            # Handle computed fields
            for new_field, operation in computed_fields.items():
                try:
                    if operation["type"] == "sum":
                        row[new_field] = sum([getattr(obj, f, 0) or 0 for f in operation["fields"]])
                    elif operation["type"] == "concat":
                        row[new_field] = " ".join([str(getattr(obj, f, "")) for f in operation["fields"]])
                    # Add more operation types here if needed
                except Exception:
                    row[new_field] = None

            row["id"] = obj.pk
            data.append(row)

        return Response({
            "table": table_name,
            "count": len(data),
            "data": data
        }, status=status.HTTP_200_OK)
    

class EntryAnalysesSchemaView(APIView):
    def get(self, request, entry_id):
        entry = get_object_or_404(models.DynamicFormEntry, pk=entry_id)

        analyses_data = []
        for analysis in entry.analyses.all():
            comps = []
            for comp in analysis.components.all():
                if comp.listname:
                    try:
                        lst = models.List.objects.get(name=comp.listname)
                        choices = list(lst.values.values_list("value", flat=True))
                    except models.List.DoesNotExist:
                        choices = []
                else:
                    choices = None

                comps.append({
                    "id": comp.id,
                    "name": comp.name,
                    "type": comp.type,
                    "unit": {
                        "id": comp.unit.id,
                        "name": comp.unit.name
                    } if comp.unit else None,
                    "minimum": comp.minimum,
                    "maximum": comp.maximum,
                    "decimal_places": comp.decimal_places,
                    "required": not comp.optional,
                    "choices": choices,
                    "specifications": comp.spec_limits,
                    "calculated": comp.calculated,
                })

            analyses_data.append({
                "analysis_id": analysis.id,
                "analysis_name": analysis.name,
                "components": comps
            })

        return Response({
            "entry_id": entry.id,
            "analyses": analyses_data
        })


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from app import models
from app.serializers import ComponentResultSerializer


class AnalysisResultSubmitView(TrackUserMixin,APIView):
    def post(self, request, entry_id, analysis_id):
        entry = get_object_or_404(models.DynamicFormEntry, pk=entry_id)
        analysis = get_object_or_404(models.Analysis, pk=analysis_id)

        # ✅ Ensure analysis belongs to this entry
        if not entry.analyses.filter(id=analysis.id).exists():
            return Response(
                {"error": "This analysis is not linked with the entry"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 🔹 Save comment if provided
        comment = request.data.get("comment")
        if comment:
            entry.comment = comment
            entry.save(update_fields=["comment"])

        results_data = request.data.get("results", [])
        saved_results = []

        # 1️⃣ Save user-entered values for non-calculated components
        for res in results_data:
            comp_id = res.get("component_id")
            comp = get_object_or_404(models.Component, pk=comp_id, analysis=analysis)

            if comp.calculated:
                continue  # skip user input for calculated fields

            # ✅ Validate list-type components
            if comp.type.lower() == "list":
                allowed_choices = comp.spec_limits or []
                if res.get("value") not in allowed_choices:
                    return Response(
                        {
                            "error": f"Invalid choice '{res.get('value')}' for component {comp.name}. "
                                     f"Allowed values are: {allowed_choices}"
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                numeric_val = None
            else:
                numeric_val = res.get("numeric_value")

            # ✅ Save or update result
            result, _ = models.ComponentResult.objects.update_or_create(
                entry=entry,
                component=comp,
                defaults={
                    "value": res.get("value"),
                    "numeric_value": numeric_val,
                    "created_by": request.user,
                },
            )
            saved_results.append(result)

        # 2️⃣ Auto-calculate results
        calculated_components = analysis.components.filter(
            calculated=True, custom_function__isnull=False
        )

        for comp in calculated_components:
            param_values = {}
            for param in comp.function_parameters.all():
                mapped_result = models.ComponentResult.objects.filter(
                    entry=entry, component=param.mapped_component
                ).first()
                if not mapped_result or mapped_result.numeric_value is None:
                    param_values[param.parameter] = 0
                else:
                    param_values[param.parameter] = mapped_result.numeric_value

            missing_vars = [v for v in comp.custom_function.variables if v not in param_values]
            if missing_vars:
                return Response(
                    {"error": f"Missing input for variables: {', '.join(missing_vars)}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                numeric_value = comp.custom_function.evaluate(**param_values)
            except Exception as e:
                return Response(
                    {"error": f"Failed to calculate value for {comp.name}: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            result, _ = models.ComponentResult.objects.update_or_create(
                entry=entry,
                component=comp,
                defaults={
                    "value": str(numeric_value),
                    "numeric_value": numeric_value,
                    "remarks": "Auto-calculated",
                    "authorization_flag": False,
                    "authorization_remark": None,
                    "created_by": request.user,
                },
            )
            saved_results.append(result)

        # ✅ Status update logic
        has_any_analysis = entry.analyses.exists()
        has_any_result = models.ComponentResult.objects.filter(entry=entry).exists()

        if has_any_analysis and has_any_result:
            if entry.status not in ["completed", "cancelled"]:
                entry.status = "in_progress"
                entry.save(update_fields=["status"])
        else:
            if entry.status != "received":
                entry.status = "received"
                entry.save(update_fields=["status"])

        serializer = ComponentResultSerializer(saved_results, many=True)
        return Response(
            {
                "message": "Results saved successfully",
                "entry_id": entry.id,
                "analysis_id": analysis.id,
                "comment": entry.comment,
                "status": entry.status,  # ✅ return updated status too
                "results": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    # ------------------------------------------------------------
    def get(self, request, entry_id, analysis_id):
        entry = get_object_or_404(models.DynamicFormEntry, pk=entry_id)
        analysis = get_object_or_404(models.Analysis, pk=analysis_id)

        if not entry.analyses.filter(id=analysis.id).exists():
            return Response(
                {"error": "This analysis is not linked with the entry"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        results = models.ComponentResult.objects.filter(
            entry=entry, component__analysis=analysis
        )
        serializer = ComponentResultSerializer(results, many=True)

        return Response(
            {
                "message": "Results fetched successfully",
                "entry_id": entry.id,
                "analysis_id": analysis.id,
                "results": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    # ------------------------------------------------------------
    def patch(self, request, entry_id, analysis_id):
        entry = get_object_or_404(models.DynamicFormEntry, pk=entry_id)
        analysis = get_object_or_404(models.Analysis, pk=analysis_id)

        if not entry.analyses.filter(id=analysis.id).exists():
            return Response(
                {"error": "This analysis is not linked with the entry"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        comp_id = request.data.get("component_id")
        if not comp_id:
            return Response(
                {"error": "component_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        comp = get_object_or_404(models.Component, pk=comp_id, analysis=analysis)
        result = models.ComponentResult.objects.filter(entry=entry, component=comp).first()

        if not result:
            return Response(
                {"error": f"No result found for component {comp.name}"},
                status=status.HTTP_404_NOT_FOUND,
            )

        remarks = request.data.get("remarks")
        auth_flag = request.data.get("authorization_flag")
        auth_remark = request.data.get("authorization_remark")

        # ✅ 1️⃣ User can always update remarks
        if remarks is not None:
            result.remarks = remarks

        # ✅ 2️⃣ User cannot enable authorization_flag until remarks are set
        if auth_flag is not None:
            if not result.remarks:
                return Response(
                    {"error": "Add remarks before enabling authorization."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            result.authorization_flag = bool(auth_flag)

        # ✅ 3️⃣ User cannot add authorization_remark unless authorization_flag is True
        if auth_remark is not None:
            if not result.authorization_flag:
                return Response(
                    {"error": "Enable authorization flag before adding authorization remark."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            result.authorization_remark = auth_remark

        result.save()

        serializer = ComponentResultSerializer(result)
        return Response(
            {
                "message": f"Result updated successfully for component {comp.name}",
                "entry_id": entry.id,
                "analysis_id": analysis.id,
                "result": serializer.data,
            },
            status=status.HTTP_200_OK,
        )



class SystemConfigurationListCreateView(generics.ListCreateAPIView):
    queryset = models.SystemConfiguration.objects.all()
    serializer_class = SystemConfigurationSerializer
    # permission_classes = [IsAdminUser]



class SystemConfigurationDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = models.SystemConfiguration.objects.all()
    serializer_class = SystemConfigurationSerializer
    # permission_classes = [IsAdminUser]



class BulkConfigUpdateView(TrackUserMixin,APIView):
    def patch(self, request):
        
        configs_data = request.data.get("configs", [])

        if not configs_data:
            return Response({"error": "No configs provided"}, status=status.HTTP_400_BAD_REQUEST)

        updated_items = []
        errors = []

        for config_data in configs_data:
            serializer = BulkConfigUpdateSerializer(data=config_data)
            if serializer.is_valid():
                try:
                    config = models.SystemConfiguration.objects.get(id=serializer.validated_data['id'])
                    config.value = serializer.validated_data['value']
                    config.save()
                    updated_items.append(SystemConfigurationSerializer(config).data)
                except models.Config.DoesNotExist:
                    errors.append({"id": serializer.validated_data['id'], "error": "Config not found"})
            else:
                errors.append({"data": config_data, "errors": serializer.errors})

        return Response({
            "updated": updated_items,
            "errors": errors
        }, status=status.HTTP_200_OK)
    



from django.apps import apps
from django.db.models import Count, Sum, Avg, F
from slick_reporting.generator import ReportGenerator
from rest_framework.views import APIView
from rest_framework.response import Response


AGGREGATION_MAP = {
    "Count": Count,
    "Sum": Sum,
    "Avg": Avg,
    # SQLite safe: no StringAgg or ArrayAgg
}


class MultiDynamicReportView(APIView):
    def post(self, request):
        reports_config = request.data.get("reports", [])
        report_results = {}

        for report_def in reports_config:
            app_label = report_def.get("app_label")
            model_name = report_def.get("model")
            group_by = report_def.get("group_by", [])
            columns = report_def.get("columns", [])

            try:
                # 🔹 Model load
                model = apps.get_model(app_label, model_name)

                normalized_columns = []
                annotations = {}

                for col in columns:
                    if isinstance(col, str):
                        # Direct field
                        normalized_columns.append(col)
                    elif isinstance(col, dict):
                        field = col.get("field")
                        func = col.get("func")
                        alias = col.get("alias", field)

                        if func in AGGREGATION_MAP:
                            annotations[alias] = AGGREGATION_MAP[func](field)
                            normalized_columns.append(alias)
                        else:
                            # Unsupported aggregate → fallback
                            annotations[alias] = Count(field)
                            normalized_columns.append(alias)
                    else:
                        raise ValueError(f"Invalid column definition: {col}")

                # group_by fields ko bhi ensure karo
                for g in group_by:
                    if g not in normalized_columns:
                        normalized_columns.append(g)

                # 🔹 Query build (SQLite safe)
                qs = (
                    model.objects.values(*group_by)
                    .annotate(**annotations)
                    .order_by(*group_by)
                )

                # 🔹 Report format
                data = list(qs.values(*normalized_columns))
                report_results[model_name] = data

            except Exception as e:
                report_results[model_name] = {"error": str(e)}

        return Response({"reports": report_results})




from django.http import HttpResponse
import csv
from io import StringIO

class ActivityViewSet(viewsets.ModelViewSet):
    queryset = models.Activity.objects.all().order_by("-created_at")
    serializer_class = ActivitySerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["get"], url_path="export-csv")
    def export_to_csv(self, request):
        """Export all activity logs to a downloadable CSV file"""
        activities = self.get_queryset()

        # ✅ Create in-memory CSV file
        buffer = StringIO()
        writer = csv.writer(buffer)

        # ✅ Write header
        writer.writerow(["User Name", "Model Name", "Object ID", "Action", "Description", "Created At"])

        # ✅ Write rows
        for activity in activities:
            writer.writerow([
                activity.user.name if activity.user else "Anonymous",
                activity.model_name,
                activity.object_id or "",
                activity.action,
                activity.description or "",
                activity.created_at.strftime("%Y-%m-%d %H:%M:%S") if activity.created_at else "",
            ])

        # ✅ Prepare downloadable response
        response = HttpResponse(buffer.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="activity_logs.csv"'

        return response



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpResponse
from rest_framework.permissions import AllowAny
from weasyprint import HTML, CSS
import tempfile
import os


class HTMLToPDFView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        html_content = request.data.get("html")
        css_content = request.data.get("css")

        if not html_content:
            return Response(
                {"error": "HTML content is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Create temp file safely on Windows
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
                temp_path = temp_pdf.name

            # Generate the PDF
            if css_content:
                HTML(string=html_content).write_pdf(
                    target=temp_path,
                    stylesheets=[CSS(string=css_content)]
                )
            else:
                HTML(string=html_content).write_pdf(target=temp_path)

            # Read generated PDF data
            with open(temp_path, "rb") as f:
                pdf_data = f.read()

            # Delete temp file
            os.remove(temp_path)

            # Return response with download trigger
            response = HttpResponse(pdf_data, content_type="application/pdf")
            response["Content-Disposition"] = 'attachment; filename="generated.pdf"'
            response["Content-Length"] = len(pdf_data)
            return response

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





# from django.apps import apps
# from django.db.models import Count, Sum, Avg
# from slick_reporting.fields import ComputationField
# from slick_reporting.generator import ReportGenerator
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import IsAuthenticated
# from rest_framework import serializers


# AGGREGATION_MAP = {
#     "Count": Count,
#     "Sum": Sum,
#     "Avg": Avg,
# }

# class MultiDynamicReportView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         serializer = MultiReportSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         reports_data = serializer.validated_data["reports"]

#         all_results = {}

#         for report_def in reports_data:
#             try:
#                 model = apps.get_model(app_label=report_def["app_label"], model_name=report_def["model"])
#             except LookupError:
#                 all_results[f'{report_def["model"]}'] = {"error": "Model not found"}
#                 continue

#             # Gather fields
#             columns = []
#             for col in report_def["columns"]:
#                 if isinstance(col, str):
#                     columns.append(col)
#                 elif isinstance(col, dict):
#                     agg_func = AGGREGATION_MAP.get(col.get("func"))
#                     if not agg_func:
#                         all_results[report_def["model"]] = {"error": f"Unsupported aggregation function: {col.get('func')}"}
#                         continue

#                     columns.append(
#                         ComputationField.create(
#                             method=agg_func,
#                             field=col["field"],
#                             name=col.get("alias", f"{col['field']}_{col['func']}"),
#                             verbose_name=col.get(
#                                 "verbose_name",
#                                 col.get("alias", f"{col['field']}_{col['func']}")
#                             ),
#                         )
#                     )

#             group_by = report_def.get("group_by", [])
#             if isinstance(group_by, str):
#                 group_by = [group_by]
#             group_by_str = ",".join(group_by)

#             # Ensure group_by fields are in columns
#             existing_column_names = [
#                 col if isinstance(col, str) else col.name for col in columns
#             ]
#             for g in group_by:
#                 if g not in existing_column_names:
#                     columns.append(g)



#             try:
#                 report = ReportGenerator(
#                     report_model=model,
#                     date_field=report_def["date_field"],
#                     group_by=group_by_str,
#                     columns=columns,
#                     start_date=report_def.get("date_from"),
#                     end_date=report_def.get("date_to"),
#                 )
#                 results = list(report.get_report_data())
#                 all_results[report_def["model"]] = results
#             except Exception as e:
#                 all_results[report_def["model"]] = {"error": str(e)}

#         return Response({"reports": all_results})

