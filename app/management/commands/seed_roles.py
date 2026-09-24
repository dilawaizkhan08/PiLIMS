from django.core.management.base import BaseCommand
from django.db import transaction
from django.apps import apps

from app import models


class Command(BaseCommand):
    help = "Seed roles and permissions"

    ROLE_DATA = {
        "name": "Admin1",
        "users": [1],
        "permissions": [
            # User
            {"module": "app_user", "action": "create"},
            {"module": "app_user", "action": "view"},
            {"module": "app_user", "action": "update"},
            {"module": "app_user", "action": "delete"},

            # User Group
            {"module": "app_usergroup", "action": "create"},
            {"module": "app_usergroup", "action": "view"},
            {"module": "app_usergroup", "action": "update"},
            {"module": "app_usergroup", "action": "delete"},

            # Test Method
            {"module": "app_testmethod", "action": "create"},
            {"module": "app_testmethod", "action": "view"},
            {"module": "app_testmethod", "action": "update"},
            {"module": "app_testmethod", "action": "delete"},

            # Unit
            {"module": "app_unit", "action": "create"},
            {"module": "app_unit", "action": "view"},
            {"module": "app_unit", "action": "update"},
            {"module": "app_unit", "action": "delete"},

            # List
            {"module": "app_list", "action": "create"},
            {"module": "app_list", "action": "view"},
            {"module": "app_list", "action": "update"},
            {"module": "app_list", "action": "delete"},

            # Value
            {"module": "app_value", "action": "create"},
            {"module": "app_value", "action": "view"},
            {"module": "app_value", "action": "update"},
            {"module": "app_value", "action": "delete"},

            # Preparation
            {"module": "app_preparation", "action": "create"},
            {"module": "app_preparation", "action": "view"},
            {"module": "app_preparation", "action": "update"},
            {"module": "app_preparation", "action": "delete"},

            # Nicotine Assay Report
            {"module": "app_nicotineassayreport", "action": "create"},
            {"module": "app_nicotineassayreport", "action": "view"},
            {"module": "app_nicotineassayreport", "action": "update"},
            {"module": "app_nicotineassayreport", "action": "delete"},

            # Preparation Attachment
            {"module": "app_preparationattachment", "action": "create"},
            {"module": "app_preparationattachment", "action": "view"},
            {"module": "app_preparationattachment", "action": "update"},
            {"module": "app_preparationattachment", "action": "delete"},

            # Training
            {"module": "app_training", "action": "create"},
            {"module": "app_training", "action": "view"},
            {"module": "app_training", "action": "update"},
            {"module": "app_training", "action": "delete"},

            # User Training
            {"module": "app_usertraining", "action": "create"},
            {"module": "app_usertraining", "action": "view"},
            {"module": "app_usertraining", "action": "update"},
            {"module": "app_usertraining", "action": "delete"},

            # Analysis
            {"module": "app_analysis", "action": "create"},
            {"module": "app_analysis", "action": "view"},
            {"module": "app_analysis", "action": "update"},
            {"module": "app_analysis", "action": "delete"},

            # Analysis Attachment
            {"module": "app_analysisattachment", "action": "create"},
            {"module": "app_analysisattachment", "action": "view"},
            {"module": "app_analysisattachment", "action": "update"},
            {"module": "app_analysisattachment", "action": "delete"},

            # Component
            {"module": "app_component", "action": "create"},
            {"module": "app_component", "action": "view"},
            {"module": "app_component", "action": "update"},
            {"module": "app_component", "action": "delete"},

            # Component Function Parameter
            {"module": "app_componentfunctionparameter", "action": "create"},
            {"module": "app_componentfunctionparameter", "action": "view"},
            {"module": "app_componentfunctionparameter", "action": "update"},
            {"module": "app_componentfunctionparameter", "action": "delete"},

            # Custom Function
            {"module": "app_customfunction", "action": "create"},
            {"module": "app_customfunction", "action": "view"},
            {"module": "app_customfunction", "action": "update"},
            {"module": "app_customfunction", "action": "delete"},

            # Instrument
            {"module": "app_instrument", "action": "create"},
            {"module": "app_instrument", "action": "view"},
            {"module": "app_instrument", "action": "update"},
            {"module": "app_instrument", "action": "delete"},

            # Instrument History
            {"module": "app_instrumenthistory", "action": "create"},
            {"module": "app_instrumenthistory", "action": "view"},
            {"module": "app_instrumenthistory", "action": "update"},
            {"module": "app_instrumenthistory", "action": "delete"},

            # Inventory
            {"module": "app_inventory", "action": "create"},
            {"module": "app_inventory", "action": "view"},
            {"module": "app_inventory", "action": "update"},
            {"module": "app_inventory", "action": "delete"},

            # Stock
            {"module": "app_stock", "action": "create"},
            {"module": "app_stock", "action": "view"},
            {"module": "app_stock", "action": "update"},
            {"module": "app_stock", "action": "delete"},
            {"module": "app_inventory", "action": "consume_stock"},

            # Stock Consumption
            {"module": "app_stockconsumption", "action": "create"},
            {"module": "app_stockconsumption", "action": "view"},
            {"module": "app_stockconsumption", "action": "update"},
            {"module": "app_stockconsumption", "action": "delete"},

            # Sample Form
            {"module": "app_sampleform", "action": "create"},
            {"module": "app_sampleform", "action": "view"},
            {"module": "app_sampleform", "action": "update"},
            {"module": "app_sampleform", "action": "delete"},

            # Sample Field
            {"module": "app_samplefield", "action": "create"},
            {"module": "app_samplefield", "action": "view"},
            {"module": "app_samplefield", "action": "update"},
            {"module": "app_samplefield", "action": "delete"},

            # Incoming Material Sample Inspection
            {
                "module": "incoming_material_sample_inspection",
                "action": "create",
            },
            {
                "module": "incoming_material_sample_inspection",
                "action": "view",
            },
            {
                "module": "incoming_material_sample_inspection",
                "action": "update",
            },
            {
                "module": "incoming_material_sample_inspection",
                "action": "delete",
            },

            # Dynamic Form Entry
            {"module": "app_dynamicformentry", "action": "create"},
            {"module": "app_dynamicformentry", "action": "view"},
            {"module": "app_dynamicformentry", "action": "update"},
            {"module": "app_dynamicformentry", "action": "delete"},
            {"module": "app_dynamicformentry", "action": "receive"},
            {"module": "app_dynamicformentry", "action": "result_entry"},
            {"module": "app_dynamicformentry", "action": "release"},
            {"module": "app_dynamicformentry", "action": "cancel_restore"},
            {"module": "app_dynamicformentry", "action": "reactivate"},

            # Dynamic Form Entry Analysis
            {"module": "app_dynamicformentryanalysis", "action": "create"},
            {"module": "app_dynamicformentryanalysis", "action": "view"},
            {"module": "app_dynamicformentryanalysis", "action": "update"},
            {"module": "app_dynamicformentryanalysis", "action": "delete"},

            # Dynamic Form Attachment
            {"module": "app_dynamicformattachment", "action": "create"},
            {"module": "app_dynamicformattachment", "action": "view"},
            {"module": "app_dynamicformattachment", "action": "update"},
            {"module": "app_dynamicformattachment", "action": "delete"},

            # Status History
            {"module": "app_statushistory", "action": "view"},

            # Sample Component
            {"module": "app_samplecomponent", "action": "create"},
            {"module": "app_samplecomponent", "action": "view"},
            {"module": "app_samplecomponent", "action": "update"},
            {"module": "app_samplecomponent", "action": "delete"},

            # Sample Component Function Parameter
            {
                "module": "app_samplecomponentfunctionparameter",
                "action": "create",
            },
            {
                "module": "app_samplecomponentfunctionparameter",
                "action": "view",
            },
            {
                "module": "app_samplecomponentfunctionparameter",
                "action": "update",
            },
            {
                "module": "app_samplecomponentfunctionparameter",
                "action": "delete",
            },

            # Customer
            {"module": "app_customer", "action": "create"},
            {"module": "app_customer", "action": "view"},
            {"module": "app_customer", "action": "update"},
            {"module": "app_customer", "action": "delete"},

            # Request Form
            {"module": "app_requestform", "action": "create"},
            {"module": "app_requestform", "action": "view"},
            {"module": "app_requestform", "action": "update"},
            {"module": "app_requestform", "action": "delete"},

            # Request Field
            {"module": "app_requestfield", "action": "create"},
            {"module": "app_requestfield", "action": "view"},
            {"module": "app_requestfield", "action": "update"},
            {"module": "app_requestfield", "action": "delete"},

            # Dynamic Request Entry
            {"module": "app_dynamicrequestentry", "action": "create"},
            {"module": "app_dynamicrequestentry", "action": "view"},
            {"module": "app_dynamicrequestentry", "action": "update"},
            {"module": "app_dynamicrequestentry", "action": "delete"},

            # Dynamic Request Attachment
            {"module": "app_dynamicrequestattachment", "action": "create"},
            {"module": "app_dynamicrequestattachment", "action": "view"},
            {"module": "app_dynamicrequestattachment", "action": "update"},
            {"module": "app_dynamicrequestattachment", "action": "delete"},

            # Product
            {"module": "app_product", "action": "create"},
            {"module": "app_product", "action": "view"},
            {"module": "app_product", "action": "update"},
            {"module": "app_product", "action": "delete"},

            # Sampling Point
            {"module": "app_samplingpoint", "action": "create"},
            {"module": "app_samplingpoint", "action": "view"},
            {"module": "app_samplingpoint", "action": "update"},
            {"module": "app_samplingpoint", "action": "delete"},

            # Grade
            {"module": "app_grade", "action": "create"},
            {"module": "app_grade", "action": "view"},
            {"module": "app_grade", "action": "update"},
            {"module": "app_grade", "action": "delete"},

            # Product Sampling Grade
            {"module": "app_productsamplinggrade", "action": "create"},
            {"module": "app_productsamplinggrade", "action": "view"},
            {"module": "app_productsamplinggrade", "action": "update"},
            {"module": "app_productsamplinggrade", "action": "delete"},

            # Product Sampling Grade Analysis
            {
                "module": "app_productsamplinggradeanalysis",
                "action": "create",
            },
            {
                "module": "app_productsamplinggradeanalysis",
                "action": "view",
            },
            {
                "module": "app_productsamplinggradeanalysis",
                "action": "update",
            },
            {
                "module": "app_productsamplinggradeanalysis",
                "action": "delete",
            },

            # Role
            {"module": "app_role", "action": "create"},
            {"module": "app_role", "action": "view"},
            {"module": "app_role", "action": "update"},
            {"module": "app_role", "action": "delete"},

            # Permission
            {"module": "app_permission", "action": "create"},
            {"module": "app_permission", "action": "view"},
            {"module": "app_permission", "action": "update"},
            {"module": "app_permission", "action": "delete"},

            # Component Result
            {"module": "app_componentresult", "action": "create"},
            {"module": "app_componentresult", "action": "view"},
            {"module": "app_componentresult", "action": "update"},
            {"module": "app_componentresult", "action": "delete"},

            # System Configuration
            {"module": "app_systemconfiguration", "action": "create"},
            {"module": "app_systemconfiguration", "action": "view"},
            {"module": "app_systemconfiguration", "action": "update"},
            {"module": "app_systemconfiguration", "action": "delete"},

            # Activity
            {"module": "app_activity", "action": "view"},

            # Report Template
            {"module": "app_reporttemplate", "action": "create"},
            {"module": "app_reporttemplate", "action": "view"},
            {"module": "app_reporttemplate", "action": "update"},
            {"module": "app_reporttemplate", "action": "delete"},

            # Query Report Template
            {"module": "app_queryreporttemplate", "action": "create"},
            {"module": "app_queryreporttemplate", "action": "view"},
            {"module": "app_queryreporttemplate", "action": "update"},
            {"module": "app_queryreporttemplate", "action": "delete"},

            # Generated Report
            {"module": "app_generatedreport", "action": "create"},
            {"module": "app_generatedreport", "action": "view"},
            {"module": "app_generatedreport", "action": "update"},
            {"module": "app_generatedreport", "action": "delete"},

            # Investigation
            {"module": "app_investigation", "action": "create"},
            {"module": "app_investigation", "action": "view"},
            {"module": "app_investigation", "action": "update"},
            {"module": "app_investigation", "action": "delete"},

            # Sample Analysis Result
            {"module": "app_sampleanalysisresult", "action": "create"},
            {"module": "app_sampleanalysisresult", "action": "view"},
            {"module": "app_sampleanalysisresult", "action": "update"},
            {"module": "app_sampleanalysisresult", "action": "delete"},

            # Inspection Approval
            {
                "module": "incoming_material_sample_inspection",
                "action": "approve",
            },
        ],
    }

    @transaction.atomic
    def handle(self, *args, **options):
        role_name = self.ROLE_DATA["name"]

        # -----------------------------
        # Validate tables
        # -----------------------------
        all_tables = {
            model._meta.db_table
            for model in apps.get_models()
        }

        invalid_modules = {
            permission["module"]
            for permission in self.ROLE_DATA["permissions"]
            if permission["module"] not in all_tables
        }

        if invalid_modules:
            self.stdout.write(
                self.style.ERROR(
                    "Invalid modules found:\n"
                    + "\n".join(sorted(invalid_modules))
                )
            )
            return

        # -----------------------------
        # Get/Create Role
        # -----------------------------
        role, created = models.Role.objects.get_or_create(
            name=role_name
        )

        if created:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Role '{role_name}' created."
                )
            )
        else:
            self.stdout.write(
                self.style.WARNING(
                    f"Role '{role_name}' already exists. Updating..."
                )
            )

        # -----------------------------
        # Assign Users
        # -----------------------------
        users = models.User.objects.filter(
            id__in=self.ROLE_DATA["users"]
        )

        role.users.set(users)

        self.stdout.write(
            f"Assigned {users.count()} user(s) to '{role_name}'."
        )

        # -----------------------------
        # Seed Permissions
        # -----------------------------
        role.permissions.all().delete()

        permissions_created = 0

        for permission_data in self.ROLE_DATA["permissions"]:
            models.Permission.objects.create(
                role=role,
                module=permission_data["module"],
                action=permission_data["action"],
            )

            permissions_created += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"{permissions_created} permissions seeded."
            )
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Role '{role_name}' seeded successfully."
            )
        )