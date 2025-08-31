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
            user = authenticate(request, email=email, password=password)

            if user and user.is_active:
                token, _ = Token.objects.get_or_create(user=user)
                update_last_login(None, user)

                user_data = UserSerializer(user, context={'request': request}).data
                return Response({
                    "token": token.key,
                    "user": user_data,
                }, status=status.HTTP_200_OK)

            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserViewSet(viewsets.ModelViewSet):
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
        


class AnalysisViewSet(viewsets.ModelViewSet):
    queryset = models.Analysis.objects.all()
    serializer_class = AnalysisSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        analysis = serializer.save()

        # Handle multiple files from 'attachments'
        files = request.FILES.getlist("attachments")
        for f in files:
            models.AnalysisAttachment.objects.create(analysis=analysis, file=f)

        return Response(self.get_serializer(analysis).data, status=status.HTTP_201_CREATED)



class CustomFunctionViewSet(viewsets.ModelViewSet):
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
        # Check if last validated matches the incoming request
        last_valid = request.session.get("last_valid_function")
        if not last_valid or last_valid != request.data:
            return Response(
                {"error": "Please validate the function before saving."},
                status=400
            )
        # proceed to save
        return super().create(request, *args, **kwargs)



class InstrumentViewSet(viewsets.ModelViewSet):
    queryset = models.Instrument.objects.all()
    serializer_class = InstrumentSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

class InstrumentHistoryViewSet(viewsets.ModelViewSet):
    queryset = models.InstrumentHistory.objects.all()
    serializer_class = InstrumentHistorySerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class InventoryViewSet(viewsets.ModelViewSet):
    queryset = models.Inventory.objects.all()
    serializer_class = InventorySerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class StockViewSet(viewsets.ModelViewSet):
    queryset = models.Stock.objects.all()
    serializer_class = StockSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

class UnitViewSet(viewsets.ModelViewSet):
    queryset = models.Unit.objects.all()
    serializer_class = UnitSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

class CustomerViewSet(viewsets.ModelViewSet):
    queryset = models.Customer.objects.all().order_by('-created_at')
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated,HasModulePermission] 


class ListViewSet(viewsets.ModelViewSet):
    queryset = models.List.objects.all()
    serializer_class = ListSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class ValueViewSet(viewsets.ModelViewSet):
    queryset = models.Value.objects.all()
    serializer_class = ValueSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class UserGroupViewSet(viewsets.ModelViewSet):
    queryset = models.UserGroup.objects.all()
    serializer_class = UserGroupSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]


class TestMethodViewSet(viewsets.ModelViewSet):
    queryset = models.TestMethod.objects.all()
    serializer_class = TestMethodSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

class ComponentViewSet(viewsets.ModelViewSet):
    queryset = models.Component.objects.all()
    serializer_class = ComponentSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]



from django.apps import apps

class SampleFormViewSet(viewsets.ModelViewSet):
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
    permission_classes = [IsAuthenticated,HasModulePermission]

    def get(self, request, form_id):
        sample_form = get_object_or_404(models.SampleForm, pk=form_id)
        fields_qs = sample_form.fields.all()

        serializer_class = build_dynamic_serializer(fields_qs)
        serializer_instance = serializer_class()

        field_meta = []
        for sample_field in fields_qs:
            # Get serializer field for type info
            field_obj = serializer_instance.get_fields().get(sample_field.field_name)

            meta = {
                "name": sample_field.field_name,
                "type": field_obj.__class__.__name__ if field_obj else None,
                "required": sample_field.required,  # ✅ from DB
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
    permission_classes = [IsAuthenticated,HasModulePermission]
    def post(self, request, form_id):
        sample_form = get_object_or_404(models.SampleForm, pk=form_id)
        serializer_class = build_dynamic_serializer(sample_form.fields.all())
        serializer = serializer_class(data=request.data)

        if serializer.is_valid():
            clean_data = convert_datetimes_to_strings(serializer.validated_data)

            # ✅ Create entry
            entry = models.DynamicFormEntry.objects.create(
                form=sample_form,
                data=clean_data,
                logged_by=request.user
            )

            # ✅ Handle analyses if provided
            analyses = request.data.get("analyses", [])
            if analyses:
                entry.analyses.set(models.Analysis.objects.filter(id__in=analyses))

            return Response({"message": "Form submitted successfully"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class DynamicSampleFormEntryViewSet(viewsets.ModelViewSet):
    queryset = models.DynamicFormEntry.objects.all().order_by("-created_at")
    serializer_class = DynamicFormEntrySerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

    # extra endpoint to update status (like your Action dropdown)
     
    @action(detail=False, methods=["post"])  # ✅ no pk, works on multiple
    def update_status(self, request):
        new_status = request.data.get("status")
        ids = request.data.get("ids", [])

        if not new_status or not ids:
            return Response({"error": "Both 'status' and 'ids' are required"}, status=400)

        if new_status not in dict(models.DynamicFormEntry.STATUS_CHOICES):
            return Response({"error": "Invalid status"}, status=400)

        # ✅ Bulk update
        updated_count = models.DynamicFormEntry.objects.filter(id__in=ids).update(status=new_status)

        return Response({
            "message": f"Status updated to '{new_status}' for {updated_count} entries",
            "updated_ids": ids
        })


class RequestFormViewSet(viewsets.ModelViewSet):
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
    permission_classes = [IsAuthenticated,HasModulePermission]
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

        # ------------------ ATTACHED SAMPLE FORM ------------------
        sample_form_meta = None
        if request_form.sample_form:
            sample_form = request_form.sample_form
            sample_fields_qs = sample_form.fields.all()

            sample_serializer_class = build_dynamic_serializer(sample_fields_qs)
            sample_serializer_instance = sample_serializer_class()

            sample_field_meta = []
            for sample_field in sample_fields_qs:
                field_obj = sample_serializer_instance.get_fields().get(sample_field.field_name)
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

            sample_form_meta = {
                "form_name": sample_form.sample_name,
                "fields": sample_field_meta
            }

        # ------------------ RESPONSE ------------------
        return Response({
            "form_name": request_form.request_name,
            "fields": req_field_meta,
            "sample_form": sample_form_meta
        })


def convert_datetimes_to_strings(data):
    new_data = {}
    for k, v in data.items():
        if isinstance(v, datetime):
            new_data[k] = v.isoformat()
        else:
            new_data[k] = v
    return new_data


from django.db import transaction

class RequestFormSubmitView(APIView):
    permission_classes = [IsAuthenticated,HasModulePermission]
    def post(self, request, form_id):
        request_form = get_object_or_404(models.RequestForm, pk=form_id)

        # ------------------ VALIDATE REQUEST FORM ------------------
        req_serializer_class = build_dynamic_request_serializer(request_form.fields.all())
        req_serializer = req_serializer_class(data=request.data.get("request_form", {}))
        req_serializer.is_valid(raise_exception=True)
        req_clean_data = convert_datetimes_to_strings(req_serializer.validated_data)

        # ------------------ VALIDATE MULTIPLE SAMPLE FORMS ------------------
        sample_clean_list = []
        if request_form.sample_form and "sample_forms" in request.data:
            sample_form = request_form.sample_form
            sample_serializer_class = build_dynamic_serializer(sample_form.fields.all())

            for sample in request.data.get("sample_forms", []):
                sample_serializer = sample_serializer_class(data=sample)
                sample_serializer.is_valid(raise_exception=True)
                sample_clean_list.append(
                    convert_datetimes_to_strings(sample_serializer.validated_data)
                )

        # ------------------ SAVE ENTRY ------------------
        entry = models.DynamicRequestEntry.objects.create(
            request_form=request_form,
            data={
                "request_form": req_clean_data,
                "sample_forms": sample_clean_list
            },
            logged_by=request.user
        )

        # Handle analyses if provided
        analyses = request.data.get("analyses", [])
        if analyses:
            entry.analyses.set(models.Analysis.objects.filter(id__in=analyses))

        return Response(DynamicRequestEntrySerializer(entry).data, status=status.HTTP_201_CREATED)


class DynamicRequestFormEntryViewSet(viewsets.ModelViewSet):
    queryset = models.DynamicRequestEntry.objects.all().order_by("-created_at")
    serializer_class = DynamicRequestEntrySerializer
    permission_classes = [IsAuthenticated,HasModulePermission]

    # extra endpoint to update status (like your Action dropdown)
    @action(detail=True, methods=["post"])
    def update_status(self, request, pk=None):
        entry = self.get_object()
        new_status = request.data.get("status")

        if new_status not in dict(models.DynamicRequestEntry.STATUS_CHOICES):
            return Response({"error": "Invalid status"}, status=400)

        entry.status = new_status
        entry.save()
        return Response({"message": f"Status updated to {new_status}"})



class ProductViewSet(viewsets.ModelViewSet):
    queryset = models.Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated,HasModulePermission]
    


class RoleViewSet(viewsets.ModelViewSet):
    queryset = models.Role.objects.all()
    serializer_class = RoleSerializer

from rest_framework import viewsets, mixins
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
