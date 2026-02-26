import uuid
from django.db import transaction, IntegrityError
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
from django.contrib.auth import authenticate
from .models import User
from .serializers import *
import ast
from rest_framework import serializers, viewsets
from django.shortcuts import get_object_or_404
from app import models
from .serializers import build_dynamic_request_serializer, build_dynamic_serializer
from django.apps import apps
from django.core.serializers import serialize
import json
from datetime import datetime, date
import inflection
from rest_framework import viewsets, mixins
from django.db.models import F
from app.mixins import TrackUserMixin
from django.http import HttpResponse
import csv
from io import StringIO
from weasyprint import HTML, CSS
import tempfile
import os,base64
from django.db.models import Count, Sum, Avg, Q, F, ExpressionWrapper, DurationField
from .filters import GenericSearchFilter
from .utility import create_entry_analyses,update_status_with_history

from app.serializers import ComponentResultSerializer
from app.user_limit import check_user_limit
from django.template import Template, Context
from django.utils.text import slugify
from django.db.models.query import QuerySet
from datetime import timedelta
from django.db.models.functions import TruncMonth, Now
import calendar
from django.db import connection
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from jinja2 import Template as JinjaTemplate
from .pagination import CustomPageNumberPagination
import logging
logger = logging.getLogger(__name__)



def get_config(key, default=None):
    from .models import SystemConfiguration
    config = SystemConfiguration.objects.filter(key=key).first()
    return config.value if config else default

class RegisterView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            check_user_limit()
            user = serializer.save()

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
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "Invalid credentials"}, status=401)

        if not user.is_active:
            return Response(
                {"error": "Your account is deactivated. Please contact admin."},
                status=403,
            )

        max_attempts = int(get_config("max_wrong_password_attempts", 5))
        user_auth = authenticate(request, email=email, password=password)

        if user_auth:
            # Reset failed login attempts
            user_auth.failed_login_attempts = 0
            user_auth.last_activity = timezone.now()
            user_auth.save(update_fields=["failed_login_attempts", "last_activity"])

            # Safe token handling
            token = Token.objects.filter(user=user_auth).first()
            if not token:
                try:
                    token = Token.objects.create(user=user_auth)
                except IntegrityError:
                    token = Token.objects.get(user=user_auth)

            update_last_login(None, user_auth)
            user_data = UserSerializer(user_auth, context={"request": request}).data
            return Response({"token": token.key, "user": user_data}, status=200)

        # Wrong password handling
        user.failed_login_attempts = F("failed_login_attempts") + 1
        user.save(update_fields=["failed_login_attempts"])
        user.refresh_from_db()

        if user.failed_login_attempts >= max_attempts:
            user.is_active = False
            user.save(update_fields=["is_active"])
            return Response(
                {
                    "error": "Your account has been locked due to too many failed login attempts."
                },
                status=403,
            )

        remaining = max_attempts - user.failed_login_attempts
        return Response(
            {"error": f"Invalid credentials. You have {remaining} attempts left."},
            status=401,
        )


class UserViewSet(TrackUserMixin, viewsets.ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    filter_backends = [SearchFilter, DjangoFilterBackend, GenericSearchFilter]
    search_fields = ['email', 'name']
    filterset_fields = ['is_active', 'role']
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        # Only return users created by the logged-in user
        return User.objects.filter(created_by=self.request.user)

    def perform_create(self, serializer):
        check_user_limit()
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
        if not user.is_active:
            check_user_limit()
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
    pagination_class = CustomPageNumberPagination

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
    permission_classes = [IsAuthenticated, HasModulePermission]

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


class AnalysisViewSet(TrackUserMixin, viewsets.ModelViewSet):
    queryset = models.Analysis.objects.all()
    serializer_class = AnalysisSerializer
    permission_classes = [IsAuthenticated, HasModulePermission]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        user = self.request.user

        # Superusers OR Admins see everything
        if user.is_superuser or user.role == "Admin":
            return models.Analysis.objects.all()

        # Normal users → filter by user_groups
        return models.Analysis.objects.filter(
            user_groups__in=user.user_groups.all()
        ).distinct()


class CustomFunctionViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.CustomFunction.objects.all()
    serializer_class = CustomFunctionSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

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
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination


    def get_queryset(self):
        user = self.request.user

        # Superusers OR Admins → full access
        if user.is_superuser or user.role == "Admin":
            return models.Instrument.objects.all()

        # Normal users → only instruments in their user_groups
        return models.Instrument.objects.filter(
            user_groups__in=user.user_groups.all()
        ).distinct()


class InstrumentHistoryViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.InstrumentHistory.objects.all()
    serializer_class = InstrumentHistorySerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    filter_backends = [GenericSearchFilter]


class InventoryViewSet(TrackUserMixin, viewsets.ModelViewSet):
    queryset = models.Inventory.objects.all()
    serializer_class = InventorySerializer
    permission_classes = [IsAuthenticated, HasModulePermission]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        user = self.request.user

        # Superadmins & Admins → full access
        if user.is_superuser or user.role == "Admin":
            return models.Inventory.objects.all()

        # Normal users → only inventories in their user_groups
        return models.Inventory.objects.filter(
            user_groups__in=user.user_groups.all()
        ).distinct()


class StockViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Stock.objects.all()
    serializer_class = StockSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    filter_backends = [GenericSearchFilter]


class UnitViewSet(TrackUserMixin, viewsets.ModelViewSet):
    queryset = models.Unit.objects.all()
    serializer_class = UnitSerializer
    permission_classes = [IsAuthenticated, HasModulePermission]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        user = self.request.user

        # Superusers OR admin users see everything
        if user.is_superuser or user.role == "Admin":
            return models.Unit.objects.all()

        # Normal users → filter by user_groups
        return models.Unit.objects.filter(
            user_groups__in=user.user_groups.all()
        ).distinct()


class CustomerViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Customer.objects.all().order_by('-created_at')
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated,HasModulePermission] 
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

    
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


class ListViewSet(TrackUserMixin, viewsets.ModelViewSet):
    queryset = models.List.objects.all()
    serializer_class = ListSerializer
    permission_classes = [IsAuthenticated, HasModulePermission]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        user = self.request.user

        # Superusers OR admin users → see everything
        if user.is_superuser or user.role == "Admin":
            return models.List.objects.all()

        # Normal users → only lists matching their user_groups
        return models.List.objects.filter(
            user_groups__in=user.user_groups.all()
        ).distinct()


class ValueViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Value.objects.all()
    serializer_class = ValueSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    filter_backends = [GenericSearchFilter]


class UserGroupViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.UserGroup.objects.all()
    serializer_class = UserGroupSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination


class TestMethodViewSet(TrackUserMixin, viewsets.ModelViewSet):
    queryset = models.TestMethod.objects.all()
    serializer_class = TestMethodSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        user = self.request.user

        # Superusers OR admin users see everything
        if user.is_superuser or user.role == "Admin":
            return models.TestMethod.objects.all()

        # Normal users → filter by user_groups
        return models.TestMethod.objects.filter(
            user_groups__in=user.user_groups.all()
        ).distinct()

    
class ComponentViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Component.objects.all()
    serializer_class = ComponentSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    filter_backends = [GenericSearchFilter]


class SampleFormViewSet(TrackUserMixin, viewsets.ModelViewSet):
    queryset = models.SampleForm.objects.all()
    serializer_class = SampleFormSerializer
    permission_classes = [IsAuthenticated, HasModulePermission]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        user = self.request.user

        # Superadmins & Admin role → full access
        if user.is_superuser or user.role == "Admin":
            return models.SampleForm.objects.all()

        # Normal users → show only their user_group items
        return models.SampleForm.objects.filter(
            user_groups__in=user.user_groups.all()
        ).distinct()

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

    def post(self, request, form_id, repetition):

        sample_form = get_object_or_404(models.SampleForm, pk=form_id)

        if repetition < 1:
            return Response({"error": "Repetition must be ≥ 1"}, status=400)

        serializer_class = build_dynamic_serializer(sample_form.fields.all())
        serializer = serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        all_entries = []

        for _ in range(repetition):

            entry = models.DynamicFormEntry.objects.create(
                form=sample_form,
                data={},
                logged_by=request.user
            )

            clean_data = {"form_id": sample_form.id}
            auto_analysis_ids = set()   # 🔹 product based analyses

            # ----------------------------------
            #  HANDLE FORM FIELDS
            # ----------------------------------
            for field in sample_form.fields.all():

                value = (
                    request.FILES.getlist(field.field_name)
                    if field.field_property == "attachment"
                    else serializer.validated_data.get(field.field_name)
                )

                # 1️⃣ ATTACHMENTS
                if field.field_property == "attachment" and value:
                    file_urls = []
                    for f in value:
                        attachment = models.DynamicFormAttachment.objects.create(
                            entry=entry,
                            field=field,
                            file=f
                        )
                        file_urls.append(attachment.file.url)
                    clean_data[field.field_name] = file_urls
                    continue

                # 2️⃣ DATETIME
                if isinstance(value, datetime):
                    clean_data[field.field_name] = value.isoformat()
                    continue

                # 3️⃣ LINK TO PRODUCT → AUTO ANALYSES
                if (
                    field.field_property == "link_to_table"
                    and field.link_to_table == "app_product"
                    and value
                ):
                    clean_data[field.field_name] = value
                    try:
                        product = models.Product.objects.get(id=value)

                        product_analysis_ids = (
                            models.ProductSamplingGradeAnalysis.objects
                            .filter(product_sampling_grade__product=product)
                            .values_list("analysis_id", flat=True)
                            .distinct()
                        )

                        auto_analysis_ids.update(product_analysis_ids)

                    except models.Product.DoesNotExist:
                        pass

                    continue

                # 4️⃣ NORMAL FIELD
                clean_data[field.field_name] = value

            # ----------------------------------
            #  MANUAL + AUTO ANALYSES (DB ONLY)
            # ----------------------------------
            manual_analyses = request.data.getlist("analyses")
            manual_ids = {int(x) for x in manual_analyses} if manual_analyses else set()

            final_analysis_ids = manual_ids.union(auto_analysis_ids)

            if final_analysis_ids:
                entry.analyses.set(
                    models.Analysis.objects.filter(id__in=final_analysis_ids)
                )

                # 🔥 AUTO CREATE entry_analyses + sample_components
                create_entry_analyses(entry, final_analysis_ids)

            # ----------------------------------
            #  SAVE ENTRY DATA (RESPONSE SAME)
            # ----------------------------------
            if manual_analyses:
                clean_data["analyses"] = list(manual_ids)

            entry.data = clean_data
            entry.save()

            all_entries.append({
                "entry_id": entry.id,
                "data": entry.data
            })

        # ----------------------------------
        #  RESPONSE (UNCHANGED)
        # ----------------------------------
        message_lines = [
            f"Sample with id {entry['entry_id']} submitted successfully"
            for entry in all_entries
        ]

        return Response({
            "messages": message_lines,
            "form_id": sample_form.id,
            "repetition": repetition,
            "entries": all_entries
        }, status=status.HTTP_201_CREATED)


class DynamicSampleFormEntryViewSet(viewsets.ModelViewSet):
    queryset = models.DynamicFormEntry.objects.all().order_by("-created_at")
    serializer_class = DynamicFormEntrySerializer
    permission_classes = [IsAuthenticated, HasModulePermission]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

    # -----------------------------
    # Update Status Endpoint
    # -----------------------------
    @action(detail=False, methods=["post"])
    def update_status(self, request):
        new_status = request.data.get("status")
        ids = request.data.get("ids", [])
        analyst_id = request.data.get("analyst_id")  # for assign_analyst

        if not new_status or not ids:
            return Response({"error": "status and ids are required"}, status=400)

        # -----------------------------
        # Map status → permission action
        # -----------------------------
        status_permission_map = {
            "received": "receive",
            "in_progress": "result_entry",
            "completed": "result_entry",
            "assign_analyst": "update",
            "authorized": "authorize",
            "rejected": "authorize",
            "hold": "cancel_restore",
            "unhold": "cancel_restore",
            "reactivate": "reactivate",
        }

        required_permission = status_permission_map.get(new_status)
        module_name = models.DynamicFormEntry._meta.db_table

        if required_permission:
            has_permission = False
            for role in request.user.roles.all():
                if role.permissions.filter(module=module_name, action=required_permission).exists():
                    has_permission = True
                    break
            if not has_permission and not request.user.is_superuser:
                return Response(
                    {"error": f"You do not have permission to set status '{new_status}'."},
                    status=403
                )

        valid_statuses = dict(models.DynamicFormEntry.STATUS_CHOICES)
        if new_status not in valid_statuses and new_status not in ["unhold", "assign_analyst"]:
            return Response({"error": "Invalid status"}, status=400)

        entries = models.DynamicFormEntry.objects.filter(id__in=ids)
        user = request.user

        # -----------------------------
        # Handle assign_analyst separately
        # -----------------------------
        if new_status == "assign_analyst":
            if not analyst_id:
                return Response({"error": "analyst_id is required when assigning analyst"}, status=400)

            try:
                analyst = models.User.objects.get(id=analyst_id)
            except models.User.DoesNotExist:
                return Response({"error": f"Analyst with id {analyst_id} not found"}, status=404)

            for entry in entries:
                if entry.status != "received":
                    return Response({
                        "error": f"Entry {entry.id} must be 'received' before assigning analyst."
                    }, status=400)

            # Only assign analyst (status unchanged → no history needed)
            entries.update(analyst=analyst)
            return Response({
                "message": f"Analyst {analyst.id} assigned to entries (status unchanged)",
                "updated_ids": ids
            })

        # -----------------------------
        # Normal status updates (including hold/unhold)
        # -----------------------------
        for entry in entries:

            # ❌ Completed is locked except authorize/reject/hold
            if entry.status == "completed" and new_status not in ["authorized", "rejected", "hold"]:
                return Response({
                    "error": f"Entry {entry.id} is completed and cannot be changed."
                }, status=400)

            # ❌ Authorize / Reject only if completed
            if new_status in ["authorized", "rejected"] and entry.status != "completed":
                return Response({
                    "error": f"Entry {entry.id} must be completed before {new_status}."
                }, status=400)

            # -----------------------------
            # On Hold
            # -----------------------------
            if new_status == "hold":
                if entry.status == "hold":
                    return Response({
                        "error": f"Entry {entry.id} is already on hold."
                    }, status=400)
                update_status_with_history(entry, "hold", user)
                continue

            # -----------------------------
            # Reactivate validation
            # -----------------------------
            if new_status == "reactivate":
                if entry.status not in ["authorized", "rejected"]:
                    return Response({
                        "error": f"Entry {entry.id} can only be reactivated if it is 'authorized' or 'rejected'."
                    }, status=400)
                update_status_with_history(entry, "in_progress", user)  # reactivate → reset to in_progress
                continue

            # -----------------------------
            # Unhold → restore previous status
            # -----------------------------
            if new_status == "unhold":
                if entry.status != "hold":
                    return Response({
                        "error": f"Entry {entry.id} is not on hold."
                    }, status=400)

                last_status = (
                    models.StatusHistory.objects
                    .filter(entry=entry, new_status="hold")
                    .order_by("-id")
                    .first()
                )
                restored_status = last_status.old_status if last_status else "in_progress"
                update_status_with_history(entry, restored_status, user)
                continue

            # -----------------------------
            # Normal status update
            # -----------------------------
            update_status_with_history(entry, new_status, user)

        return Response({
            "message": f"Status updated to {new_status}",
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


class SampleComponentViewSet(viewsets.ModelViewSet):
    queryset = models.SampleComponent.objects.all()
    serializer_class = SampleComponentSerializer
    permission_classes = [IsAuthenticated]

    def partial_update(self, request, *args, **kwargs):
        """Allow updating sample-specific component only"""
        return super().partial_update(request, *args, **kwargs)


class RequestFormViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.RequestForm.objects.all()
    serializer_class = RequestFormSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

    def get_queryset(self):
        user = self.request.user

        # Superadmins & Admin role → full access
        if user.is_superuser or user.role == "Admin":
            return models.RequestForm.objects.all()

        # Normal users → only items in their assigned user_groups
        return models.RequestForm.objects.filter(
            user_groups__in=user.user_groups.all()
        ).distinct()

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

            sample_form = request_form.sample_form.first()
            sample_serializer_class = build_dynamic_serializer(sample_form.fields.all())

            for sample in sample_forms_data:

                # repetition per sample (default 1)
                repetition = int(sample.get("repetition", 1))
                if repetition < 1:
                    repetition = 1

                # validate once
                sample_copy = {k: v for k, v in sample.items() if k != "repetition"}
                sample_serializer = sample_serializer_class(data=sample_copy)
                sample_serializer.is_valid(raise_exception=True)

                # create multiple sample entries
                for _ in range(repetition):

                    sample_entry = models.DynamicFormEntry.objects.create(
                        form=sample_form,
                        data={},
                        logged_by=request.user
                    )

                    clean_sample = {}

                    for field in sample_form.fields.all():

                        if field.field_property == "attachment":
                            urls = sample_copy.get(field.field_name, [])
                            if not isinstance(urls, list):
                                urls = [urls]

                            file_list = []
                            for url in urls:
                                file_path = url.split('/media/')[-1]

                                # Create new DynamicFormAttachment
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

                    # append each repeated sample entry separately
                    sample_clean_list.append({
                        "id": sample_entry.id,
                        **clean_sample
                    })

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
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination

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
            "sample_forms": [
                {"id": e.id, **e.data} for e in sample_entry_list
            ]
        }
        entry.save()

        return Response(DynamicRequestEntrySerializer(entry, context={"request": request}).data)

    @action(detail=False, methods=["post"])
    def update_status(self, request):
        new_status = request.data.get("status")
        ids = request.data.get("ids", [])

        # ---------------------------
        # 1️⃣ Basic validation
        # ---------------------------
        if not new_status or not ids:
            return Response(
                {"error": "Both 'status' and 'ids' are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ---------------------------
        # 2️⃣ Map status → permission action (As per your pattern)
        # ---------------------------
        status_permission_map = {
            "received": "receive",
            "authorized": "authorize",
            "rejected": "authorize",
            "cancelled": "cancel_restore",
            "restored": "cancel_restore",
        }

        required_permission = status_permission_map.get(new_status)
        module_name = models.DynamicRequestEntry._meta.db_table

        # ---------------------------
        # 3️⃣ Check Permissions
        # ---------------------------
        if required_permission:
            has_permission = False
            for role in request.user.roles.all():
                if role.permissions.filter(module=module_name, action=required_permission).exists():
                    has_permission = True
                    break
            
            if not has_permission and not request.user.is_superuser:
                return Response(
                    {"error": f"You do not have permission to set status '{new_status}'."},
                    status=status.HTTP_403_FORBIDDEN
                )

        # ---------------------------
        # 4️⃣ Validate status is valid
        # ---------------------------
        valid_statuses = dict(models.DynamicRequestEntry.STATUS_CHOICES)
        if new_status not in valid_statuses:
            return Response(
                {"error": f"Invalid status '{new_status}'"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ---------------------------
        # 5️⃣ Allowed manual transitions
        # ---------------------------
        allowed_manual = ["received", "authorized", "rejected", "cancelled", "restored"]

        if new_status not in allowed_manual:
            return Response(
                {"error": f"Cannot manually change status to '{new_status}'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ---------------------------
        # 6️⃣ Fetch entries & Validate transition rules
        # ---------------------------
        entries = models.DynamicRequestEntry.objects.filter(id__in=ids)

        for entry in entries:
            # Rule 1: initiated can ONLY go to received
            if entry.status == "initiated" and new_status != "received":
                return Response(
                    {"error": f"Request {entry.id} is 'initiated' and can only be updated to 'received'."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # ---------------------------
        # 7️⃣ Perform update (Iterative to keep History if needed)
        # ---------------------------
        # Agar aapko history track karni hai jaisa upar wale code mein tha:
        for entry in entries:
            # Optional: StatusHistory log yahan add karein agar model available hai
            entry.status = new_status
            entry.save(update_fields=["status"])

        return Response(
            {
                "message": f"Status updated to '{new_status}' for {entries.count()} request(s)",
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



class SamplingPointViewSet(viewsets.ModelViewSet):
    queryset = models.SamplingPoint.objects.all()
    serializer_class = SamplingPointSerializer
    permission_classes = [IsAuthenticated, HasModulePermission]

class GradeViewSet(viewsets.ModelViewSet):
    queryset = models.Grade.objects.all()
    serializer_class = GradeSerializer
    permission_classes = [IsAuthenticated, HasModulePermission]

class ProductViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination


    def get_queryset(self):
        user = self.request.user

        # Superadmins & Admin role → full access
        if user.is_superuser or user.role == "Admin":
            return models.Product.objects.all()

        # Normal users → only those in their assigned user groups
        return models.Product.objects.filter(
            user_groups__in=user.user_groups.all()
        ).distinct()


class RoleViewSet(TrackUserMixin,viewsets.ModelViewSet):
    queryset = models.Role.objects.all()
    serializer_class = RoleSerializer
    filter_backends = [GenericSearchFilter]
    pagination_class = CustomPageNumberPagination


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
    permission_classes = []

    def post(self, request, *args, **kwargs):
        table_name = request.data.get("table_name")
        requested_fields = request.data.get("fields")
        computed_fields = request.data.get("computed_fields", {})
        product_id = request.data.get("product_id")

        if not table_name:
            return Response(
                {"error": "table_name is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # =========================================================
        # 🔴 SPECIAL CASE: app_grade & app_samplingpoint
        # =========================================================
        if table_name in ["app_grade", "app_samplingpoint"]:

            if not product_id:
                return Response(
                    {"error": "product_id is required for this table"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                product = models.Product.objects.get(id=product_id)
            except models.Product.DoesNotExist:
                return Response(
                    {"error": "Product not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            psg_qs = models.ProductSamplingGrade.objects.filter(
                product_id=product_id
            )

            data = []

            # ---------- GRADES ----------
            if table_name == "app_grade":
                rows = (
                    psg_qs
                    .select_related("grade")
                    .values(
                        "grade__id",
                        "grade__name"
                    )
                    .distinct()
                )

                for r in rows:
                    data.append({
                        "id": r["grade__id"],
                        "name": r["grade__name"],
                        "product": {
                            "id": product.id,
                            "name": product.name,
                            "version": product.version,
                        }
                    })

            # ---------- SAMPLING POINTS ----------
            elif table_name == "app_samplingpoint":
                rows = (
                    psg_qs
                    .select_related("sampling_point")
                    .values(
                        "sampling_point__id",
                        "sampling_point__name"
                    )
                    .distinct()
                )

                for r in rows:
                    data.append({
                        "id": r["sampling_point__id"],
                        "name": r["sampling_point__name"],
                        "product": {
                            "id": product.id,
                            "name": product.name,
                            "version": product.version,
                        }
                    })

            return Response({
                "table": table_name,
                "count": len(data),
                "data": data
            }, status=status.HTTP_200_OK)

        # =========================================================
        # 🟢 DEFAULT / GENERIC DYNAMIC HANDLER
        # =========================================================
        try:
            if "_" not in table_name:
                return Response(
                    {"error": f"Invalid table_name format: {table_name}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            app_label, model_snake = table_name.split("_", 1)
            model_name = inflection.camelize(model_snake)
            model = apps.get_model(app_label, model_name)

        except LookupError:
            return Response(
                {"error": f"Model '{table_name}' not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        objects = model.objects.all()
        data = []

        all_field_names = [
            f.name for f in model._meta.get_fields()
            if not f.auto_created or f.concrete
        ]

        fields_to_use = requested_fields or all_field_names

        for obj in objects:
            row = {}

            for field_name in fields_to_use:
                try:
                    field = model._meta.get_field(field_name)
                    value = getattr(obj, field_name, None)

                    # ManyToMany
                    if field.many_to_many:
                        value = [str(v) for v in value.all()]

                    # ForeignKey / OneToOne
                    elif field.one_to_one or field.many_to_one:
                        if value:
                            for attr in ["name", "username", "email"]:
                                if hasattr(value, attr):
                                    value = getattr(value, attr)
                                    break
                            else:
                                value = str(value)
                        else:
                            value = None

                    # File / Image
                    elif isinstance(field, (models.FileField, models.ImageField)):
                        value = value.url if value else None

                    row[field_name] = value if value not in ["", None] else None

                except Exception:
                    val = getattr(obj, field_name, None)
                    row[field_name] = str(val) if val is not None else None

            # -------- Computed Fields --------
            for new_field, operation in computed_fields.items():
                try:
                    if operation["type"] == "sum":
                        row[new_field] = sum(
                            (getattr(obj, f, 0) or 0)
                            for f in operation["fields"]
                        )
                    elif operation["type"] == "concat":
                        row[new_field] = " ".join(
                            str(getattr(obj, f, "") or "")
                            for f in operation["fields"]
                        ).strip()
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
    """
    Returns analyses and their components for a given entry,
    including analysis-level status.
    """
    def get(self, request, entry_id):
        entry = get_object_or_404(models.DynamicFormEntry, pk=entry_id)

        analyses_data = []

        entry_analyses = models.DynamicFormEntryAnalysis.objects.filter(
            entry=entry
        ).select_related("analysis").prefetch_related(
            "sample_components__component"
        )

        for ea in entry_analyses:
            comps = []
            for sc in ea.sample_components.all():
                comp = sc.component
                choices = sc.spec_limits if comp.type.lower() == "list" else None

                # Optionally include result for each component if it exists
                result = models.ComponentResult.objects.filter(
                    entry=entry,
                    sample_component=sc
                ).first()

                comps.append({
                    "id": sc.id,  # Sample Component ID
                    "name": sc.name,
                    "type": comp.type,
                    "unit": {"id": sc.unit.id, "name": sc.unit.name} if sc.unit else None,
                    "minimum": sc.minimum,
                    "maximum": sc.maximum,
                    "decimal_places": sc.decimal_places,
                    "required": not sc.optional,
                    "choices": choices,
                    "specifications": sc.spec_limits,
                    "calculated": comp.calculated,
                    "value": result.value if result else None,
                    "numeric_value": result.numeric_value if result else None,
                    "authorization_flag": result.authorization_flag if result else None,
                    "remarks": result.remarks if result else None,
                    "authorization_remark": result.authorization_remark if result else None,
                })

            # ---------------------------
            # Compute analysis-level status
            # ---------------------------
            components = ea.sample_components.all()

            if not components.exists():
                analysis_status = "initiated"
            else:
                any_result_entered = False
                all_authorized = True
                for sc in components:
                    r = models.ComponentResult.objects.filter(entry=entry, sample_component=sc).first()
                    if not r or r.value in [None, ""]:
                        all_authorized = False
                    else:
                        any_result_entered = True
                        if not r.authorization_flag:
                            all_authorized = False

                if not any_result_entered:
                    analysis_status = "initiated"
                elif all_authorized:
                    analysis_status = "authorized"
                else:
                    analysis_status = "completed"

            analyses_data.append({
                "analysis_id": ea.analysis.id,
                "analysis_name": ea.analysis.name,
                "components": comps,
                "analysis_status": analysis_status  # ✅ Added
            })

        return Response({
            "entry_id": entry.id,
            "comment": entry.comment,
            "analyses": analyses_data
        })


class AnalysisResultSubmitView(TrackUserMixin, APIView):
    """
    Submit results for an analysis, automatically calculating dependent fields
    and updating entry status based on completion and spec limits.
    """
    permission_classes = [IsAuthenticated, HasModulePermission]

    def post(self, request, entry_id):
        entry = get_object_or_404(models.DynamicFormEntry, pk=entry_id)

        # -----------------------------
        # Check if user has 'result_entry' permission
        # -----------------------------
        module_name = models.DynamicFormEntry._meta.db_table
        has_permission = request.user.is_superuser or any(
            role.permissions.filter(module=module_name, action="result_entry").exists()
            for role in request.user.roles.all()
        )

        if not has_permission:
            return Response(
                {"error": "You do not have permission to enter results for this module."},
                status=status.HTTP_403_FORBIDDEN
            )

        if entry.status == "hold":
            return Response(
                {"error": "Entry is on hold. Results cannot be submitted."},
                status=status.HTTP_400_BAD_REQUEST
            )

        analyses_data = request.data.get("analyses", [])
        all_saved_results = []
        all_errors = []

        # ---------------------------
        # Update entry comment
        # ---------------------------
        comment = request.data.get("comment")
        if comment:
            entry.comment = comment
            entry.save(update_fields=["comment"])

        # ---------------------------
        # Loop each analysis
        # ---------------------------
        for analysis_item in analyses_data:
            analysis_id = analysis_item.get("analysis_id")
            if not analysis_id:
                all_errors.append("Missing analysis_id in one of the analyses.")
                continue

            entry_analysis = get_object_or_404(
                models.DynamicFormEntryAnalysis,
                entry=entry,
                analysis_id=analysis_id
            )

            results_data = analysis_item.get("results", [])
            saved_results = []
            errors = []

            # 1️⃣ Save user-entered results
            for res in results_data:
                sc_id = res.get("component_id")
                if not sc_id:
                    errors.append("Missing component_id in payload")
                    continue

                try:
                    sc = models.SampleComponent.objects.get(
                        pk=sc_id,
                        entry_analysis=entry_analysis
                    )
                except models.SampleComponent.DoesNotExist:
                    errors.append(f"SampleComponent {sc_id} not found in analysis {analysis_id}")
                    continue

                numeric_value = None
                try:
                    if res.get("numeric_value") not in [None, ""]:
                        numeric_value = float(res.get("numeric_value"))
                except ValueError:
                    errors.append(f"{sc.name}: invalid numeric value")
                    continue

                existing_result = models.ComponentResult.objects.filter(
                    entry=entry,
                    sample_component=sc
                ).first()

                if existing_result:
                    existing_result.value = res.get("value")
                    existing_result.numeric_value = numeric_value
                    existing_result.created_by = request.user
                    existing_result.save()
                    saved_results.append(existing_result)
                else:
                    new_result = models.ComponentResult.objects.create(
                        entry=entry,
                        sample_component=sc,
                        value=res.get("value"),
                        numeric_value=numeric_value,
                        created_by=request.user
                    )
                    saved_results.append(new_result)

            # 2️⃣ Auto-calculate calculated components
            calculated_components = entry_analysis.sample_components.filter(
                calculated=True,
                custom_function__isnull=False
            ).prefetch_related("function_parameters__mapped_sample_component")

            for sc in calculated_components:
                param_values = {}
                missing_input = False

                for param in sc.function_parameters.all():
                    mapped_result = next(
                        (r for r in saved_results if r.sample_component_id == param.mapped_sample_component.id),
                        None
                    )
                    if not mapped_result:
                        mapped_result = models.ComponentResult.objects.filter(
                            entry=entry,
                            sample_component=param.mapped_sample_component
                        ).first()

                    if not mapped_result or mapped_result.numeric_value is None:
                        errors.append(f"{sc.name}: missing input for variable '{param.parameter}'")
                        missing_input = True
                        break

                    param_values[param.parameter] = mapped_result.numeric_value

                if missing_input:
                    continue

                try:
                    numeric_value = sc.custom_function.evaluate(**param_values)
                except Exception as e:
                    errors.append(f"{sc.name}: Error executing function: {str(e)}")
                    continue

                existing_calc_result = models.ComponentResult.objects.filter(
                    entry=entry,
                    sample_component=sc
                ).first()

                if existing_calc_result:
                    existing_calc_result.value = str(numeric_value)
                    existing_calc_result.numeric_value = numeric_value
                    existing_calc_result.remarks = "Auto-calculated"
                    existing_calc_result.authorization_flag = False
                    existing_calc_result.authorization_remark = None
                    existing_calc_result.created_by = request.user
                    existing_calc_result.save()
                    saved_results.append(existing_calc_result)
                else:
                    new_calc_result = models.ComponentResult.objects.create(
                        entry=entry,
                        sample_component=sc,
                        value=str(numeric_value),
                        numeric_value=numeric_value,
                        remarks="Auto-calculated",
                        authorization_flag=False,
                        authorization_remark=None,
                        created_by=request.user
                    )
                    saved_results.append(new_calc_result)

            all_saved_results.extend(saved_results)
            all_errors.extend(errors)

        # ---------------------------
        # Update overall entry status
        # ---------------------------

        def update_entry_status(entry_obj, user):
            entry_analyses = models.DynamicFormEntryAnalysis.objects.filter(entry=entry_obj)

            total_components = 0
            filled_components = 0
            all_authorized = True

            for ea in entry_analyses:
                sample_components = ea.sample_components.all()
                total_components += sample_components.count()

                for sc in sample_components:
                    result = models.ComponentResult.objects.filter(
                        entry=entry_obj,
                        sample_component=sc
                    ).first()

                    # Check if filled
                    if result and (result.value not in [None, ""] or result.numeric_value is not None):
                        filled_components += 1
                        if not result.authorization_flag:
                            all_authorized = False
                    else:
                        all_authorized = False

            # ✅ Final Decision Logic
            if total_components == 0 or filled_components == 0:
                final_status = "received"
            elif filled_components < total_components:
                final_status = "in_progress"
            elif filled_components == total_components and all_authorized:
                final_status = "completed"
            else:
                final_status = "in_progress"

            # Use helper to update status and create history
            update_status_with_history(entry_obj, final_status, user)

            return final_status


        final_status = update_entry_status(entry, request.user)

        # ---------------------------
        # Analysis-level status
        # ---------------------------
        analysis_status_list = []
        entry_analyses = models.DynamicFormEntryAnalysis.objects.filter(entry=entry)

        for ea in entry_analyses:
            components = ea.sample_components.all()

            if not components.exists():
                status_ = "initiated"
            else:
                any_result_entered = False
                all_authorized = True
                for sc in components:
                    result = models.ComponentResult.objects.filter(
                        entry=entry,
                        sample_component=sc
                    ).first()
                    if not result or result.value in [None, ""]:
                        all_authorized = False
                    else:
                        any_result_entered = True
                        if not result.authorization_flag:
                            all_authorized = False

                if not any_result_entered:
                    status_ = "initiated"
                elif all_authorized:
                    status_ = "authorized"
                else:
                    status_ = "completed"

            analysis_status_list.append({
                "analysis_id": ea.analysis_id,
                "status": status_
            })

        # ---------------------------
        # Build response
        # ---------------------------
        serializer = ComponentResultSerializer(all_saved_results, many=True)

        response = {
            "message": "Results saved successfully" if not all_errors else "Saved with errors",
            "entry_id": entry.id,
            "status": final_status,
            "comment": entry.comment,
            "results": serializer.data,
            "analysis_status": analysis_status_list
        }

        if all_errors:
            response["errors"] = all_errors

        return Response(response, status=status.HTTP_200_OK)

    # ---------------------------
    # Get all results
    # ---------------------------
    def get(self, request, entry_id, analysis_id):
        entry = get_object_or_404(models.DynamicFormEntry, pk=entry_id)

        results = models.ComponentResult.objects.filter(
            entry=entry,
            sample_component__entry_analysis__analysis_id=analysis_id
        ).select_related("sample_component")

        serializer = ComponentResultSerializer(results, many=True)

        # ---------------------------
        # Analysis-level status
        # ---------------------------
        entry_analysis = get_object_or_404(
            models.DynamicFormEntryAnalysis,
            entry=entry,
            analysis_id=analysis_id
        )
        components = entry_analysis.sample_components.all()

        if not components.exists():
            analysis_status = "initiated"
        else:
            any_result_entered = False
            all_authorized = True
            for sc in components:
                result = models.ComponentResult.objects.filter(
                    entry=entry,
                    sample_component=sc
                ).first()
                if not result or result.value in [None, ""]:
                    all_authorized = False
                else:
                    any_result_entered = True
                    if not result.authorization_flag:
                        all_authorized = False

            if not any_result_entered:
                analysis_status = "initiated"
            elif all_authorized:
                analysis_status = "authorized"
            else:
                analysis_status = "completed"

        return Response({
            "message": "Results fetched successfully",
            "entry_id": entry.id,
            "analysis_id": analysis_id,
            "results": serializer.data,
            "analysis_status": analysis_status
        }, status=status.HTTP_200_OK)

    # ---------------------------
    # Update individual result remarks/authorization
    def patch(self, request, entry_id, analysis_id):
        entry = get_object_or_404(models.DynamicFormEntry, pk=entry_id)

        sc_id = request.data.get("component_id")
        if not sc_id:
            return Response({"error": "component_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        sc = get_object_or_404(
            models.SampleComponent,
            pk=sc_id,
            entry_analysis__entry=entry,
            entry_analysis__analysis_id=analysis_id
        )

        result = models.ComponentResult.objects.filter(
            entry=entry,
            sample_component=sc
        ).first()

        if not result:
            return Response({"error": f"No result found for component {sc.name}"}, status=status.HTTP_404_NOT_FOUND)

        remarks = request.data.get("remarks")
        auth_flag = request.data.get("authorization_flag")
        auth_remark = request.data.get("authorization_remark")

        if remarks is not None:
            result.remarks = remarks

        if auth_flag is not None:
            # User can authorize even without remarks
            result.authorization_flag = bool(auth_flag)

        if auth_remark is not None:
            if not result.authorization_flag:
                return Response({"error": "Enable authorization flag before adding authorization remark."}, status=status.HTTP_400_BAD_REQUEST)
            result.authorization_remark = auth_remark

        result.save()
        serializer = ComponentResultSerializer(result)

        # ---------------------------
        # Update analysis-level status after patch
        entry_analysis = get_object_or_404(
            models.DynamicFormEntryAnalysis,
            entry=entry,
            analysis_id=analysis_id
        )
        components = entry_analysis.sample_components.all()

        if not components.exists():
            analysis_status = "initiated"
        else:
            any_result_entered = False
            all_authorized = True
            for sc in components:
                r = models.ComponentResult.objects.filter(entry=entry, sample_component=sc).first()
                if not r or r.value in [None, ""]:
                    all_authorized = False
                else:
                    any_result_entered = True
                    if not r.authorization_flag:
                        all_authorized = False

            if not any_result_entered:
                analysis_status = "initiated"
            elif all_authorized:
                analysis_status = "authorized"
            else:
                analysis_status = "completed"

        return Response({
            "message": f"Result updated successfully for component {sc.name}",
            "entry_id": entry.id,
            "analysis_id": analysis_id,
            "result": serializer.data,
            "analysis_status": analysis_status
        }, status=status.HTTP_200_OK)


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
    

AGGREGATION_MAP = {
    "Count": Count,
    "Sum": Sum,
    "Avg": Avg,
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
            filters = report_def.get("filters", {})

            try:
                # 🔹 Load model
                model = apps.get_model(app_label, model_name)

                normalized_columns = []
                annotations = {}

                # 🔹 Process columns
                for col in columns:
                    if isinstance(col, str):
                        normalized_columns.append(col)
                    elif isinstance(col, dict):
                        field = col.get("field")
                        func = col.get("func")
                        alias = col.get("alias", field)

                        if func in AGGREGATION_MAP:
                            annotations[alias] = AGGREGATION_MAP[func](field)
                        else:
                            annotations[alias] = Count(field)
                        normalized_columns.append(alias)
                    else:
                        raise ValueError(f"Invalid column definition: {col}")

                # 🔹 Ensure group_by fields appear in result
                for g in group_by:
                    if g not in normalized_columns:
                        normalized_columns.append(g)

                # 🔹 Apply filters dynamically
                q_filters = Q()
                for key, value in filters.items():
                    q_filters &= Q(**{key: value})

                # 🔹 Build queryset
                qs = (
                    model.objects.filter(q_filters)
                    .values(*group_by)
                    .annotate(**annotations)
                    .order_by(*group_by)
                )

                data = list(qs.values(*normalized_columns))
                report_results[model_name] = data

            except Exception as e:
                report_results[model_name] = {"error": str(e)}

        return Response({"reports": report_results})


class MultiDynamicReportSchemaView(APIView):
    """
    Returns model field structure instead of actual data.
    Same input format as MultiDynamicReportView.
    """

    def post(self, request):
        reports_config = request.data.get("reports", [])
        report_schemas = {}

        for report_def in reports_config:
            app_label = report_def.get("app_label")
            model_name = report_def.get("model")
            group_by = report_def.get("group_by", [])
            columns = report_def.get("columns", [])

            try:
                # 🔹 Load model
                model = apps.get_model(app_label, model_name)

                # 🔹 Collect all model field names (including related fields)
                model_fields = [f.name for f in model._meta.get_fields()]

                normalized_columns = []
                annotations = {}

                # 🔹 Process columns same way (but don’t run queries)
                for col in columns:
                    if isinstance(col, str):
                        normalized_columns.append(col)
                    elif isinstance(col, dict):
                        field = col.get("field")
                        func = col.get("func")
                        alias = col.get("alias", field)
                        normalized_columns.append(alias)
                    else:
                        raise ValueError(f"Invalid column definition: {col}")

                # 🔹 Ensure group_by fields appear
                for g in group_by:
                    if g not in normalized_columns:
                        normalized_columns.append(g)

                # 🔹 Return schema info only (no DB hits)
                report_schemas[model_name] = {
                    "available_fields": model_fields,
                    "requested_fields": normalized_columns,
                }

            except Exception as e:
                report_schemas[model_name] = {"error": str(e)}

        return Response({"reports": report_schemas})


class ActivityViewSet(viewsets.ModelViewSet):
    queryset = models.Activity.objects.all().order_by("-created_at")
    serializer_class = ActivitySerializer
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPageNumberPagination

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


class HTMLToPDFView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        html_content = request.data.get("html")

        if not html_content:
            return Response(
                {"error": "HTML content is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # ✅ Backend CSS: No border, minimal margins
            backend_css = """
                @page {
                    size: A4;
                    margin: 5px; /* very small margin */
                }

                body {
                    margin: 0;
                    padding: 5px;
                    box-sizing: border-box;
                    height: 100%;
                }

                table {
                    width: 100%;
                    border-collapse: collapse;
                }

                th, td {
                    border: 1px solid #000;
                    padding: 6px;
                    text-align: center;
                    font-size: 12px;
                }

                th {
                    background-color: #f2f2f2;
                }
            """

            # Create temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
                temp_path = temp_pdf.name

            # Generate PDF with clean layout
            HTML(
                string=html_content,
                base_url=request.build_absolute_uri("/")
            ).write_pdf(
                target=temp_path,
                stylesheets=[CSS(string=backend_css)]
            )

            # Read PDF data
            with open(temp_path, "rb") as f:
                pdf_data = f.read()

            os.remove(temp_path)

            # Return PDF file
            response = HttpResponse(pdf_data, content_type="application/pdf")
            response["Content-Disposition"] = 'attachment; filename="generated.pdf"'
            response["Content-Length"] = len(pdf_data)
            return response

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



def get_nested_value(obj, attr_path):
    """
    Robust resolver for nested Django ORM paths.
    Handles:
      - dot or double-underscore paths
      - ManyToMany / reverse relations (auto .all())
      - JSONFields / dict access
    """
    if not attr_path:
        return ""

    path = attr_path.replace("__", ".")
    parts = path.split(".")
    value = obj

    for idx, part in enumerate(parts):
        if value is None:
            return ""

        # Handle dict / JSONField
        if isinstance(value, dict):
            value = value.get(part, "")
        else:
            if not hasattr(value, part):
                return ""

            value = getattr(value, part)

            # For related managers (m2m or reverse FK), call .all()
            if hasattr(value, "all") and callable(value.all):
                value = value.all()

        # Handle lists/querysets
        if isinstance(value, (QuerySet, list)):
            remaining = parts[idx + 1:]
            if not remaining:
                # Last level — convert all to strings
                return ", ".join(str(v) for v in value)

            sub_path = ".".join(remaining)
            results = [get_nested_value(v, sub_path) for v in value]
            results = [r for r in results if r]

            # Deduplicate, preserve order
            seen = set()
            ordered = []
            for r in results:
                if r not in seen:
                    seen.add(r)
                    ordered.append(r)

            return ", ".join(str(r) for r in ordered)

    if value is None:
        return ""
    if hasattr(value, "pk") and not isinstance(value, (str, int, float)):
        return str(value)
    return value


class ReportTemplateCreateView(APIView):
    """
    Create a dynamic report template.
    Accepts HTML, CSS, and nested field mappings.
    Normalizes labels to template-safe keys.
    """

    def post(self, request):
        data = request.data.copy()
        fields = data.get("fields", [])
        normalized_fields = []

        for field in fields:
            label = field.get("label", "")
            path = field.get("path", "")
            safe_label = (
                slugify(label).replace("-", "_").replace(".", "_")
            )
            normalized_fields.append({
                "label": safe_label,
                "path": path
            })

        data["fields"] = normalized_fields

        serializer = ReportTemplateSerializer(data=data)
        if serializer.is_valid():
            template = serializer.save()
            return Response({
                "message": "Template created successfully",
                "template_id": template.id,
                "normalized_fields": normalized_fields
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RenderReportView(APIView):
    """
    Render stored template for DynamicFormEntry sample.
    Returns both rendered HTML and downloadable PDF file.
    """

    def get(self, request):
        template_id = request.query_params.get("template_id")
        sample_id = request.query_params.get("sample_id")
        download = request.query_params.get("download")  # optional flag

        if not (template_id and sample_id):
            return Response(
                {"error": "template_id and sample_id required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            report_template = models.ReportTemplate.objects.get(id=template_id)
        except models.ReportTemplate.DoesNotExist:
            return Response({"error": "Template not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            entry = (
                models.DynamicFormEntry.objects
                .select_related("form", "analyst", "logged_by")
                .prefetch_related(
                    "analyses",
                    "analyses__components",
                    "form__group_analysis_list",
                    "form__group_analysis_list__user_groups",
                    "form__user_groups",
                )
                .get(id=sample_id)
            )
        except models.DynamicFormEntry.DoesNotExist:
            return Response({"error": "Sample not found"}, status=status.HTTP_404_NOT_FOUND)

        # Context
        context_data = {}
        for field in report_template.fields:
            label = field.get("label", "")
            path = field.get("path", "")
            safe_key = slugify(label).replace("-", "_").replace(".", "_")
            value = get_nested_value(entry, path)
            context_data[safe_key] = value

        # Render HTML
        html_template = Template(report_template.html_content)
        rendered_html = html_template.render(Context(context_data))
        if report_template.css_content:
            rendered_html = f"<style>{report_template.css_content}</style>\n{rendered_html}"

        # Generate PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
            temp_path = temp_pdf.name

        # Reduce default PDF margins
        custom_css = """
        @page {
            size: A4;
            margin: 10mm;
        }
        body {
            margin: 0;
            padding: 5px;
            box-sizing: border-box;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid #000;
            padding: 6px;
            text-align: center;
            font-size: 12px;
        }
        th {
            background-color: #f2f2f2;
        }
        """

        combined_css = f"{custom_css}\n{report_template.css_content or ''}"

        HTML(string=rendered_html, base_url=request.build_absolute_uri("/")).write_pdf(
            target=temp_path,
            stylesheets=[CSS(string=combined_css)]
        )


        with open(temp_path, "rb") as f:
            pdf_data = f.read()
        os.remove(temp_path)

        # ✅ If user requested ?download=true → send the actual file
        if download:
            response = HttpResponse(pdf_data, content_type="application/pdf")
            response["Content-Disposition"] = f'attachment; filename="report_{sample_id}.pdf"'
            return response

        # ✅ Otherwise, send both HTML + PDF (embedded binary)
        return HttpResponse(pdf_data, content_type="application/pdf")


class RenderRequestReportView(APIView):
    """
    GET /api/render-request-report/?template_id=&request_entry_id=&download=true
    → Executes SQL with request_entry_id
    → Renders SQL result in Jinja2 HTML + CSS → PDF
    """

    def get(self, request):
        template_id = request.query_params.get("template_id")
        request_entry_id = request.query_params.get("request_entry_id")
        download = request.query_params.get("download")

        if not (template_id and request_entry_id):
            return Response(
                {"error": "template_id and request_entry_id required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 1️⃣ Get template
        try:
            template_obj = models.QueryReportTemplate.objects.get(id=template_id)
        except models.QueryReportTemplate.DoesNotExist:
            return Response({"error": "Template not found"}, status=status.HTTP_404_NOT_FOUND)

        # 2️⃣ Check Request Entry exists
        try:
            entry = models.DynamicRequestEntry.objects.get(id=request_entry_id)
        except models.DynamicRequestEntry.DoesNotExist:
            return Response(
                {"error": f"DynamicRequestEntry {request_entry_id} not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # 3️⃣ Execute SQL
        try:
            params = {"request_entry_id": int(request_entry_id)}
            result = self.execute_query(template_obj.sql_query, params)
            if not result:
                return Response({"error": "No data returned from SQL"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(
                {"error": f"SQL execution failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # 4️⃣ Context (IMPORTANT)
        context_data = {
            "rows": result,
            "request": entry,
            **result[0]
        }

        # 5️⃣ Render HTML
        jinja_template = JinjaTemplate(template_obj.html_content)
        rendered_html = jinja_template.render(context_data)

        # 6️⃣ CSS
        default_css = """
        @page { size: A4; margin: 10mm; }
        body { font-family: Arial, sans-serif; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #000; padding: 6px; text-align: center; }
        th { background-color: #f2f2f2; }
        """
        combined_css = f"{default_css}\n{template_obj.css_content or ''}"

        # 7️⃣ PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
            temp_path = temp_pdf.name

        HTML(string=rendered_html, base_url=request.build_absolute_uri("/")).write_pdf(
            target=temp_path,
            stylesheets=[CSS(string=combined_css)]
        )

        with open(temp_path, "rb") as f:
            pdf_data = f.read()
        os.remove(temp_path)

        # 8️⃣ Response
        response = HttpResponse(pdf_data, content_type="application/pdf")
        filename = f"request_report_{request_entry_id}.pdf"
        response["Content-Disposition"] = (
            f'attachment; filename="{filename}"'
            if download else f'inline; filename="{filename}"'
        )
        return response

    # ---------------------------
    # SQL Executor
    # ---------------------------
    def execute_query(self, sql_query, params):
        with connection.cursor() as cursor:
            cursor.execute(sql_query, params)
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]


class QueryReportTemplateViewSet(viewsets.ModelViewSet):
    queryset = models.QueryReportTemplate.objects.all().order_by('-id')
    serializer_class = QueryReportTemplateSerializer

from datetime import datetime, timedelta




STATUS_CHOICES = [
    ("initiated", "Initiated"),
    ("received", "Received"),
    ("in_progress", "In Progress"),
    ("completed", "Completed"),
    ("assign_analyst", "Assign Analyst"),
    ("authorized", "Authorized"),
    ("rejected", "Rejected"),
    ("cancelled", "Cancelled"),
    ("restored", "Restored"),
]

class AnalyticsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # ===================== FILTERS =====================
        start_date_str = request.query_params.get("start_date")
        end_date_str = request.query_params.get("end_date")
        product_type = request.query_params.get("product_type")
        current_month = request.query_params.get("current_month")
        current_year = request.query_params.get("current_year")

        today = timezone.now().date()

        # Default date range
        if not start_date_str or not end_date_str:
            start_date = today - timedelta(days=90)
            end_date = today
        else:
            try:
                start_date = datetime.fromisoformat(start_date_str).date()
                end_date = datetime.fromisoformat(end_date_str).date()
            except ValueError:
                return Response({"error": "Invalid date format. Use YYYY-MM-DD."}, status=400)

        # Override for current month
        if current_month == "true":
            start_date = today.replace(day=1)
            end_date = today

        # Override for current year
        if current_year == "true":
            start_date = today.replace(month=1, day=1)
            end_date = today

        if end_date < start_date:
            return Response({"error": "end_date must be greater than or equal to start_date."}, status=400)

        # ===================== ENTRIES FILTER =====================
        entries_qs = models.DynamicFormEntry.objects.filter(
            created_at__date__range=(start_date, end_date)
        )

        # Filter by product type dynamically
        if product_type:
            filtered_entries = []
            for entry in entries_qs:
                form = entry.form
                include_entry = False
                for pf in form.fields.filter(field_property="link_to_table"):
                    value = entry.data.get(pf.field_name)
                    if value is not None:
                        values = value if isinstance(value, list) else [value]
                        for v in values:
                            try:
                                product_id = int(v)
                                product_obj = models.Product.objects.get(id=product_id)
                                if product_obj.product_type == product_type:
                                    include_entry = True
                                    break
                            except (ValueError, models.Product.DoesNotExist):
                                continue
                    if include_entry:
                        break
                if include_entry:
                    filtered_entries.append(entry.id)
            entries_qs = entries_qs.filter(id__in=filtered_entries)

        # ===================== CARDS =====================
        total_users = models.User.objects.count()
        active_users = models.User.objects.filter(is_active=True).count()
        total_analyses = models.Analysis.objects.count()
        total_products = models.Product.objects.count()

        total_entries = entries_qs.count()
        completed_entries = entries_qs.filter(status="completed").count()
        pending_entries = entries_qs.exclude(status="completed").count()

        comps = models.Component.objects.values("analysis").annotate(cnt=Count("id"))
        avg_components_per_analysis = float(comps.aggregate(avg=Avg("cnt"))["avg"] or 0)

        completed_age_agg = entries_qs.filter(status="completed").annotate(
            age=ExpressionWrapper(Now() - F("created_at"), output_field=DurationField())
        ).aggregate(avg_age=Avg("age"))["avg_age"]

        avg_completion_days = round(completed_age_agg.total_seconds() / 86400, 2) if completed_age_agg else None

        # ===================== CHARTS =====================
        monthly_entries_qs = entries_qs.annotate(
            month=TruncMonth("created_at")
        ).values("month").annotate(count=Count("id")).order_by("month")

        monthly_data = {item["month"].month: item["count"] for item in monthly_entries_qs}
        current_year_val = today.year
        monthly_entries = [
            {"month": f"{calendar.month_name[m]} {current_year_val}", "count": monthly_data.get(m, 0)}
            for m in range(1, 13)
        ]

        status_distribution_qs = entries_qs.values("status").annotate(count=Count("id"))
        actual_status_counts = {item["status"]: item["count"] for item in status_distribution_qs}
        status_distribution = {display_name: actual_status_counts.get(key, 0) for key, display_name in STATUS_CHOICES}

        top_analyses_qs = models.Analysis.objects.annotate(
            entries_count=Count("entries", filter=Q(entries__id__in=entries_qs.values_list("id", flat=True)))
        ).order_by("-entries_count")[:3]
        top_analyses = [{"analysis": a.name, "entries": a.entries_count} for a in top_analyses_qs]

        top_components_qs = models.Component.objects.annotate(
            result_count=Count("sample_overrides__results", filter=Q(sample_overrides__results__id__in=entries_qs.values_list("id", flat=True)))
        ).order_by("-result_count")[:3]
        top_components = [{"component": c.name, "analysis": c.analysis.name if c.analysis else None, "result_count": c.result_count} for c in top_components_qs]

        # ===================== ALERTS =====================
        thirty_days = today + timedelta(days=30)
        instruments_due_qs = models.Instrument.objects.filter(next_calibration_date__lte=thirty_days).order_by("next_calibration_date")[:10]
        instruments_due = [{"id": ins.id, "name": ins.name, "next_calibration_date": ins.next_calibration_date.isoformat() if ins.next_calibration_date else None} for ins in instruments_due_qs] or [{"id": None, "name": "No instruments due", "next_calibration_date": None}]

        low_stock_qs = models.Inventory.objects.filter(total_quantity__lt=10).annotate(total=F("total_quantity")).order_by("total")[:10]
        low_stock = [{"id": inv.id, "name": inv.name, "total_quantity": inv.total_quantity, "location": inv.location} for inv in low_stock_qs] or [{"id": None, "name": "No low-stock items", "total_quantity": 0, "location": None}]

        # ===================== LEADERBOARDS =====================
        top_analysts_qs = models.User.objects.annotate(
            analyzed_count=Count("analyzed_samples", filter=Q(analyzed_samples__id__in=entries_qs.values_list("id", flat=True)))
        ).order_by("-analyzed_count")[:10]
        top_analysts = [{"id": u.id, "name": getattr(u, "name", u.username), "analyzed_count": u.analyzed_count} for u in top_analysts_qs]

        product_analysis_counts = models.Product.objects.annotate(
            analysis_count=Count("sampling_grades__analyses", distinct=True)
        ).order_by("-analysis_count")[:10]
        product_analysis = [{"product": p.name, "analysis_count": p.analysis_count} for p in product_analysis_counts]

        # ===================== EXTRAS =====================
        comp_numeric_avg = models.ComponentResult.objects.filter(created_at__date__range=(start_date, end_date)).aggregate(avg_numeric=Avg("numeric_value"))["avg_numeric"]
        comp_numeric_avg = float(comp_numeric_avg) if comp_numeric_avg is not None else None

        # ===================== RESPONSE =====================
        payload = {
            "filters": {"start_date": start_date.isoformat(), "end_date": end_date.isoformat()},
            "cards": {
                "total_users": total_users,
                "active_users": active_users,
                "total_analyses": total_analyses,
                "total_products": total_products,
                "total_entries": total_entries,
                "completed_entries": completed_entries,
                "pending_entries": pending_entries,
                "avg_components_per_analysis": avg_components_per_analysis,
                "avg_completion_days": avg_completion_days,
            },
            "charts": {
                "monthly_entries": monthly_entries,
                "status_distribution": status_distribution,
                "top_analyses": top_analyses,
                "top_components": top_components,
            },
            "alerts": {"instruments_due_30_days": instruments_due, "low_stock_inventories": low_stock},
            "leaderboards": {"top_analysts": top_analysts, "product_analysis_counts": product_analysis},
            "extras": {"average_component_result_numeric_value": comp_numeric_avg},
        }

        return Response(payload)
@method_decorator(csrf_exempt, name='dispatch')
class QueryReportTemplateCreateView(APIView):

    def validate_sql_query(self, sql_query, parameters):
        """
        Validate SQL before saving template.
        Replace parameters with dummy safe values and run LIMIT 1.
        """
        try:
            test_params = {}

            # Convert parameters into dummy test values
            for key, dtype in parameters.items():
                if dtype == "int":
                    test_params[key] = 1
                else:
                    test_params[key] = "test"

            # Add LIMIT 1 to avoid heavy queries
            sql_test = f"SELECT * FROM ({sql_query}) AS t LIMIT 1"

            with connection.cursor() as cursor:
                cursor.execute(sql_test, test_params)

            return None  # No error found

        except Exception as e:
            return str(e)

    def post(self, request):
        try:
            payload = request.data if hasattr(request, "data") else json.loads(request.body)

            sql_query = payload.get("sql_query", "")
            parameters = payload.get("parameters", {})

            # 1️⃣ Validate SQL before creating template
            validation_error = self.validate_sql_query(sql_query, parameters)
            if validation_error:
                return Response(
                    {"error": f"Invalid SQL query: {validation_error}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 2️⃣ Save template only if SQL OK
            template = models.QueryReportTemplate.objects.create(
                name=payload.get("name"),
                raw_html_content=payload.get("raw_html_content"),
                jinja_html_content=payload.get("jinja_html_content"),
                css_content=payload.get("css_content", ""),
                sql_query=sql_query,
                fields=payload.get("fields", []),
                parameters=parameters,
                output_format=payload.get("output_format", "pdf"),
            )

            return Response({
                "message": "Template created successfully",
                "template_id": template.id
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


import qrcode
import base64
from io import BytesIO


class QueryReportRenderView(APIView):
    """
    GET /api/reports/render/?template_id=&sample_id=&download=true
    → Executes SQL with sample_id = DynamicFormEntry.id
    → Renders SQL result in Jinja2 HTML + CSS → PDF
    """

    def get(self, request):
        template_id = request.query_params.get("template_id")
        sample_id = request.query_params.get("sample_id")
        download = request.query_params.get("download")

        if not (template_id and sample_id):
            return Response(
                {"error": "template_id and sample_id required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 1️⃣ Get report template
        try:
            template_obj = models.QueryReportTemplate.objects.get(id=template_id)
        except models.QueryReportTemplate.DoesNotExist:
            return Response({"error": "Template not found"}, status=status.HTTP_404_NOT_FOUND)

        # 2️⃣ Check if DynamicFormEntry exists
        try:
            entry = models.DynamicFormEntry.objects.get(id=sample_id)
        except models.DynamicFormEntry.DoesNotExist:
            return Response({"error": f"DynamicFormEntry {sample_id} not found"}, status=status.HTTP_404_NOT_FOUND)

        # 3️⃣ Execute SQL query (pass sample_id to it)
        try:
            params = {"sample_id": int(sample_id)}
            result = self.execute_query(template_obj.sql_query, params)
            if not result:
                return Response({"error": "No data returned from SQL"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"SQL execution failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 4️⃣ Parse JSON field from SQL result
        if "data" in result[0]:
            try:
                parsed_data = json.loads(result[0]["data"])
            except Exception:
                parsed_data = {}
        else:
            parsed_data = {}

        # 5️⃣ Prepare context for Jinja2
        context_data = {
            "rows": result,           # analysis rows
            "entry": entry,           # DynamicFormEntry instance
            "data": parsed_data,      # parsed JSON fields
            "secondary_id": entry.secondary_id,
            "created_at": entry.created_at
        }

        # 5️⃣a Generate QR code for this sample
        qr_url = f"{settings.FRONTEND_BASE_URL}/sample-details/{sample_id}"
        qr = qrcode.QRCode(box_size=3, border=1)
        qr.add_data(qr_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        buffer.close()

        context_data["qr_code"] = f"data:image/png;base64,{qr_base64}"
        context_data["sample_url"] = qr_url

        # 6️⃣ Render HTML with Jinja2
        jinja_template = JinjaTemplate(template_obj.jinja_html_content)
        rendered_html = jinja_template.render(context_data)

        # 7️⃣ Add CSS
        default_css = """
        @page { size: A4; margin: 10mm; }
        body { font-family: Arial, sans-serif; margin: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #000; padding: 6px; text-align: left; font-size: 12px; }
        th { background-color: #f2f2f2; }
        .qr-code { position: absolute; top: 10px; right: 10px; width: 80px; height: 80px; }
        """
        combined_css = f"{default_css}\n{template_obj.css_content or ''}"

        # 7️⃣a Inject QR code at top-right
        qr_html = f'<img class="qr-code" src="{context_data["qr_code"]}" alt="Sample QR">'
        rendered_html = qr_html + rendered_html

        # 8️⃣ Generate PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
            temp_path = temp_pdf.name

        HTML(string=rendered_html, base_url=request.build_absolute_uri("/")).write_pdf(
            target=temp_path,
            stylesheets=[CSS(string=combined_css)]
        )

        with open(temp_path, "rb") as f:
            pdf_data = f.read()
        os.remove(temp_path)

        # 9️⃣ Return response
        response = HttpResponse(pdf_data, content_type="application/pdf")
        filename = f"report_entry_{sample_id}.pdf"
        response["Content-Disposition"] = (
            f'attachment; filename="{filename}"' if download else f'inline; filename="{filename}"'
        )
        return response

    # -----------------------------------
    # Helper: Execute SQL safely
    # -----------------------------------
    def execute_query(self, sql_query, params):
        """
        Execute user-defined SQL safely.
        SQL must include placeholders like %(sample_id)s
        """
        with connection.cursor() as cursor:
            cursor.execute(sql_query, params)
            columns = [col[0] for col in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return rows

class DatabaseStructureView(APIView):
    def get(self, request):
        tables = []

        for model in apps.get_models():
            table_name = model._meta.db_table
            fields = []

            for field in model._meta.get_fields():

                # Skip reverse relations
                if not hasattr(field, "column") or field.column is None:
                    continue

                fields.append({
                    "name": field.column,
                    "type": field.get_internal_type()
                })

            tables.append({
                "table_name": table_name,
                "fields": fields
            })

        return Response({"tables": tables})


class AddCommentToRequest(APIView):

    def post(self, request, request_id):
        try:
            entry = models.DynamicRequestEntry.objects.get(id=request_id)
        except models.DynamicRequestEntry.DoesNotExist:
            return Response({"error": "Request entry not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AddCommentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        entry.comment = serializer.validated_data["comment"]
        entry.save()

        return Response({"message": "Comment added successfully"}, status=status.HTTP_200_OK)



class DynamicFormEntryCompactTicketPDFView(APIView):
    """
    GET /api/samples/compact-ticket-pdf/?sample_id=&download=true
    """

    def get(self, request):
        sample_id = request.query_params.get("sample_id")
        download = request.query_params.get("download")

        if not sample_id:
            return Response({"error": "sample_id required"}, status=400)

        entry = get_object_or_404(models.DynamicFormEntry, id=sample_id)

        # ---------------- QR CODE ----------------
        qr_url = f"{settings.FRONTEND_BASE_URL}/sample-details/{entry.id}"
        qr = qrcode.QRCode(box_size=3, border=1)
        qr.add_data(qr_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        buffer.close()

        # ---------------- HTML ----------------
        html_content = f"""
<html>
<head>
<style>
  @page {{
      size: 100mm 37.5mm;  /* width:height = 4:1.5 */
      margin: 0;
  }}
  body {{
      font-family: Arial;
      font-size:8px;
      margin:0;
      padding:0;
  }}
  .container {{
      display: flex;
      flex-direction: row;  /* horizontal layout */
      align-items: flex-start;
      gap: 3mm;
      padding: 2mm;
  }}
  .qr {{
      flex: none;
  }}
  .details {{
      flex: 1;
      line-height: 1.1;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="qr">
    <img src="data:image/png;base64,{qr_base64}" width="70" height="70">
  </div>
  <div class="details">
    <strong style="font-size:10px;">{entry.form.sample_name}</strong><br/>
    <span>Secondary ID: {entry.secondary_id}</span><br/>
"""

        # Add JSON fields dynamically
        for k, v in entry.data.items():
            html_content += f"<span>{k}: {v}</span><br/>"

        html_content += """
  </div>
</div>
</body>
</html>
"""

        # ---------------- PDF GENERATE ----------------
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp:
            temp_path = temp.name

        HTML(string=html_content).write_pdf(
            temp_path,
            stylesheets=[CSS(string="@page { size: 100mm 37.5mm; margin:0; }")]
        )

        with open(temp_path, "rb") as f:
            pdf = f.read()

        os.remove(temp_path)

        response = HttpResponse(pdf, content_type="application/pdf")
        filename = f"sample_{entry.id}_ticket.pdf"
        response["Content-Disposition"] = (
            f'attachment; filename="{filename}"' if download else f'inline; filename="{filename}"'
        )

        return response 



