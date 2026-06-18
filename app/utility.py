
from django.core.mail import send_mail
from project import settings
from rest_framework.response import Response
from rest_framework import status
from smtplib import SMTPException
import logging
from app import models
import json
import os
import tempfile
from io import BytesIO

from django.db import connection
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage

from jinja2 import Template as JinjaTemplate
from weasyprint import HTML
import re
from datetime import datetime




# paginate queryset generic function
def paginate_queryset(request, view, queryset, serializer_class):
    page = view.paginate_queryset(queryset)
    if page is not None:
        serializer = serializer_class(page, many=True, context={"request": request})
        return view.get_paginated_response(serializer.data)
    serializer = serializer_class(queryset, many=True, context={"request": request})
    return Response(serializer.data)



def create_entry_analyses(entry, analysis_ids, product_id):
    from app import models

    for analysis in models.Analysis.objects.filter(id__in=analysis_ids):

        ea, _ = models.DynamicFormEntryAnalysis.objects.get_or_create(
            entry=entry,
            analysis=analysis
        )

        # ---------------------------------------------------
        # GET PRODUCT SAMPLE COMPONENTS (TEMPLATE)
        # ---------------------------------------------------
        product_components = models.SampleComponent.objects.filter(
            product_sampling_grade_analyses__product_sampling_grade__product_id=product_id,
            product_sampling_grade_analyses__analysis=analysis
        ).distinct()

        ea.components.set(product_components.values_list("component", flat=True))

        old_to_new_map = {}

        # ---------------------------------------------------
        # ALWAYS CLONE NEW SAMPLE COMPONENTS
        # ---------------------------------------------------
        for comp in product_components:

            sc = models.SampleComponent.objects.create(
                entry_analysis=ea,
                component=comp.component,

                type=comp.type,
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
                custom_function=comp.custom_function,
                acceptance_criteria=comp.acceptance_criteria,
            )

            old_to_new_map[comp.id] = sc

        # ---------------------------------------------------
        # CLONE FUNCTION PARAMETERS
        # ---------------------------------------------------
        for comp in product_components:

            if not comp.calculated:
                continue

            new_sc = old_to_new_map.get(comp.id)

            if not new_sc:
                continue

            for param in comp.component.function_parameters.all():

                mapped_sc = old_to_new_map.get(param.mapped_component.id)

                if mapped_sc:
                    models.SampleComponentFunctionParameter.objects.create(
                        sample_component=new_sc,
                        parameter=param.parameter,
                        mapped_sample_component=mapped_sc
                    )



# def create_entry_analyses(entry, analysis_ids):
#     from app import models

#     for analysis in models.Analysis.objects.filter(id__in=analysis_ids):

#         ea, _ = models.DynamicFormEntryAnalysis.objects.get_or_create(
#             entry=entry,
#             analysis=analysis
#         )

#         # ---------------------------------------------------
#         # STEP 1: GET PRODUCT SAMPLE COMPONENTS ONLY
#         # ---------------------------------------------------
#         product_components = models.SampleComponent.objects.filter(
#             product_sampling_grade_analyses__analysis=analysis
#         ).distinct()

#         # ---------------------------------------------------
#         # STEP 2: LINK TO ENTRY (NO CREATION)
#         # ---------------------------------------------------
#         ea.sample_components.set(product_components)

#         # also keep old structure consistent (if needed for frontend)
#         ea.components.set(
#             product_components.values_list("component", flat=True)
#         )

#         old_to_new_map = {
#             sc.component_id: sc for sc in product_components
#         }

#         for sc in product_components:
#             comp = sc.component
#             if not comp or not comp.calculated:
#                 continue

#             for param in comp.function_parameters.all():
#                 mapped_sc = old_to_new_map.get(param.mapped_component.id)

#                 if mapped_sc:
#                     models.SampleComponentFunctionParameter.objects.get_or_create(
#                         sample_component=sc,
#                         parameter=param.parameter,
#                         mapped_sample_component=mapped_sc
#                     )


def update_status_with_history(entry, new_status, user,reason=None):
    """
    Centralized status update with history creation.
    Only creates history if status actually changes.
    """
    if entry.status != new_status:
        old_status = entry.status
        entry.status = new_status
        entry.save(update_fields=["status"])

        models.StatusHistory.objects.create(
            entry=entry,
            old_status=old_status,
            new_status=new_status,
            updated_by=user,
            reason=reason
        )


def generate_report(template_id, sample_id, request):
    try:
        template_obj = models.QueryReportTemplate.objects.get(id=template_id)
        entry = models.DynamicFormEntry.objects.get(id=sample_id)

        params = {"sample_id": int(sample_id)}

        # Execute SQL
        with connection.cursor() as cursor:
            cursor.execute(template_obj.sql_query, params)
            columns = [col[0] for col in cursor.description]
            result = [dict(zip(columns, row)) for row in cursor.fetchall()]

        if not result:
            return None

        # Parse JSON field
        parsed_data = {}
        if "data" in result[0]:
            try:
                parsed_data = json.loads(result[0]["data"])
            except:
                pass

        context_data = {
            "rows": result,
            "entry": entry,
            "data": parsed_data,
            "sample_text_id": entry.sample_text_id,
            "created_at": entry.created_at
        }

        # Render HTML
        jinja_template = JinjaTemplate(template_obj.jinja_html_content)
        rendered_html = jinja_template.render(context_data)

        # Generate PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
            temp_path = temp_pdf.name

        HTML(string=rendered_html).write_pdf(target=temp_path)

        # Save file
        with open(temp_path, "rb") as f:
            file_content = ContentFile(f.read())

        pdf_filename = f"{template_obj.name}_entry_{sample_id}.pdf"
        pdf_path = default_storage.save(f"reports/{pdf_filename}", file_content)
        pdf_url = default_storage.url(pdf_path)

        os.remove(temp_path)

        # Save in DB (🔗 THIS IS LINK)
        models.GeneratedReport.objects.create(
            sample=entry,
            template=template_obj,
            pdf_url=pdf_url
        )

        return pdf_url

    except Exception as e:
        print(f"Report generation failed: {e}")
        return None




from datetime import datetime
from app import models


def clean(line):
    return line.replace("'", "").strip()


def split(line):
    return [p.strip() for p in line.split(",")]


def parse_date(date_str):
    return datetime.strptime(
        date_str.split(" +")[0].strip(),
        "%m/%d/%Y %I:%M:%S %p"
    )


def parse_blend_report(file_path):

    with open(file_path, "r") as f:
        lines = [clean(l) for l in f if l.strip()]

    # =========================
    # 1. PEAK RESULTS
    # =========================
    peak_records = []
    peak_section = False

    for line in lines:

        if "Peak Results" in line:
            peak_section = True
            continue

        if peak_section:

            if "Result Sign Off" in line:
                break

            parts = split(line)

            if not parts:
                continue

            if not parts[0].isdigit():
                continue

            try:
                clean_parts = [p for p in parts if p != ""]

                if len(clean_parts) < 10:
                    continue

                peak_records.append({
                    "sample_set_id": clean_parts[1],
                    "result_set_id": clean_parts[2],
                    "sample_name": clean_parts[3],
                    "compound_name": clean_parts[4],
                    "time": float(clean_parts[5]),
                    "sample_weight": float(clean_parts[6]),
                    "sku_strength": float(clean_parts[7]),
                    "area": float(clean_parts[8]),
                    "blend_amount": float(clean_parts[9]),
                })

            except Exception as e:
                print("❌ Peak error:", parts, e)

    # =========================
    # 2. SIGNOFF (FINAL FIXED)
    # =========================
    signoff_map = {}
    signoff_section = False

    for line in lines:

        if (
            "Full Name" in line and
            "Date" in line and
            "Sample Set Id" in line
        ):
            signoff_section = True
            continue

        if signoff_section:

            if "Project Name" in line:
                break

            parts = split(line)

            if not parts:
                continue

            # 🔥 REMOVE HASH ROW PROPERLY
            while parts and parts[0].strip() == "#":
                parts.pop(0)

            if len(parts) < 6:
                continue

            try:
                clean_parts = [p for p in parts if p != ""]

                sample_name = clean_parts[3]
                full_name = clean_parts[4]
                date = parse_date(clean_parts[5])

                if sample_name not in signoff_map:
                    signoff_map[sample_name] = []

                signoff_map[sample_name].append({
                    "name": full_name,
                    "date": date
                })

            except Exception as e:
                print("❌ Signoff error:", parts, e)

    print("✅ SIGNOFF MAP SIZE:", len(signoff_map))

    # =========================
    # 3. SAVE DATA
    # =========================
    for record in peak_records:

        sample = record["sample_name"]
        signoffs = signoff_map.get(sample, [])

        authored_by = authored_at = None
        approved_by = approved_at = None

        if len(signoffs) >= 1:
            authored_by = signoffs[0]["name"]
            authored_at = signoffs[0]["date"]

        if len(signoffs) >= 2:
            approved_by = signoffs[1]["name"]
            approved_at = signoffs[1]["date"]

        models.BlendReport.objects.create(
            sample_set_id=record["sample_set_id"],
            result_set_id=record["result_set_id"],
            sample_name=sample,
            compound_name=record["compound_name"],
            time=record["time"],
            sample_weight=record["sample_weight"],
            sku_strength=record["sku_strength"],
            area=record["area"],
            blend_amount=record["blend_amount"],
            authored_by=authored_by,
            authored_at=authored_at,
            approved_by=approved_by,
            approved_at=approved_at,
        )

    print("✅ DONE SUCCESSFULLY")




import pandas as pd
def to_float(value):
    try:
        return float(value)
    except:
        return None
    
def normalize(col):
    if not col:
        return ""
    return str(col).strip().lower()

def get_product(product_name):
    if not product_name:
        return None

    return models.Product.objects.filter(
        name__iexact=str(product_name).strip()
    ).first()

def build_entry_data(row, product):

    clean_data = {}

    # Product ID
    if product:
        clean_data["Product"] = product.id
        clean_data["Product Type"] = product.product_type

    # Batch
    clean_data["Batch Number"] = row.get("Batch#") or row.get("Batch Number")

    # Date fix (IMPORTANT)
    date_val = row.get("Date")
    clean_data["Manufacturing Date"] = (
        date_val.strftime("%Y-%m-%d") if hasattr(date_val, "strftime") else str(date_val)
    )

    return clean_data


def process_excel_file(file, user, sample_form):

    sheets = pd.read_excel(file, sheet_name=None)

    all_entries = []

    for sheet_name, df in sheets.items():

        df.columns = [str(c).strip() for c in df.columns]
        df = df.fillna("")

        for _, row in df.iterrows():

            product_name = row.get("Product Name")
            product = get_product(product_name)

            entry = models.DynamicFormEntry.objects.create(
                form=sample_form,
                data={},
                logged_by=user
            )

            # -------------------------
            # CLEAN DATA BUILD
            # -------------------------
            clean_data = build_entry_data(row, product)

            entry.data = clean_data
            entry.save()

            # -------------------------
            # ANALYSIS PROCESSING
            # -------------------------
            handle_analyses(entry, row)

            all_entries.append({
                "entry_id": entry.id,
                "data": clean_data
            })

    return {"created_entries": all_entries}

def handle_analyses(entry, row):

    analysis_cache = {}

    for column, value in row.items():

        col = str(column).strip()

        if col in ["Sr.", "Product Name", "Batch#", "Date"]:
            continue

        if not col:
            continue

        analysis = models.Analysis.objects.filter(name__iexact=col).first()

        if not analysis:
            continue

        if analysis.id not in analysis_cache:
            entry.analyses.add(analysis)

            entry_analysis, _ = models.DynamicFormEntryAnalysis.objects.get_or_create(
                entry=entry,
                analysis=analysis
            )

            analysis_cache[analysis.id] = entry_analysis
        else:
            entry_analysis = analysis_cache[analysis.id]

        # -------------------------
        # COMPONENTS
        # -------------------------
        for component in analysis.components.all():

            sample_component = models.SampleComponent.objects.create(
                entry_analysis=entry_analysis,
                component=component,
                name=component.name,
                type=component.type,
                unit=component.unit,
                minimum=component.minimum,
                maximum=component.maximum,
                decimal_places=component.decimal_places,
                rounding=component.rounding,
                spec_limits=component.spec_limits,
                optional=component.optional,
                calculated=component.calculated,
                default_result=component.default_result,
                acceptance_criteria=component.acceptance_criteria,
            )

            numeric = to_float(value)
            text_value = value if value != "" else None

            models.ComponentResult.objects.create(
                entry=entry,
                sample_component=sample_component,
                value=str(text_value),
                numeric_value=numeric
            )

