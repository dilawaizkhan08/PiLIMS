
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
import traceback
import qrcode
from datetime import timedelta
from django.utils import timezone
from weasyprint import HTML, CSS
import os,base64
from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage



# paginate queryset generic function
def paginate_queryset(request, view, queryset, serializer_class):
    page = view.paginate_queryset(queryset)
    if page is not None:
        serializer = serializer_class(page, many=True, context={"request": request})
        return view.get_paginated_response(serializer.data)
    serializer = serializer_class(queryset, many=True, context={"request": request})
    return Response(serializer.data)



def create_entry_analyses(entry, analysis_ids, product_id=None):
    from app import models

    if not product_id:
        for analysis in models.Analysis.objects.filter(id__in=analysis_ids):
            models.DynamicFormEntryAnalysis.objects.get_or_create(
                entry=entry,
                analysis=analysis
            )
        return

    # Get analyses in product display order
    product_analyses = (
        models.ProductSamplingGradeAnalysis.objects
        .filter(
            product_sampling_grade__product_id=product_id,
            analysis_id__in=analysis_ids
        )
        .select_related("analysis")
        .order_by("display_order")
    )

    for pa in product_analyses:
        analysis = pa.analysis

        ea, created = models.DynamicFormEntryAnalysis.objects.get_or_create(
            entry=entry,
            analysis=analysis,
            defaults={
                "display_order": pa.display_order
            }
        )

        # If already exists, keep display order in sync
        if not created and ea.display_order != pa.display_order:
            ea.display_order = pa.display_order
            ea.save(update_fields=["display_order"])

        # ---------------------------------------------------
        # GET PRODUCT SAMPLE COMPONENTS (TEMPLATE)
        # ---------------------------------------------------
        product_components = (
            models.SampleComponent.objects.filter(
                product_sampling_grade_analyses=pa
            )
            .distinct()
        )

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
            
        report = models.GeneratedReport.objects.create(
            sample=entry,
            template=template_obj
        )
        
        context_data = {
            "rows": result,
            "entry": entry,
            "data": parsed_data,
            "sample_text_id": entry.sample_text_id,
            "created_at": entry.created_at,
            "report_number": report.id,
        }

        # Render HTML
        jinja_template = JinjaTemplate(template_obj.jinja_html_content)
        rendered_html = jinja_template.render(context_data)

        default_css = """
            .report-number{
                position: fixed;
                top: 5px;
                right: 5px;
                font-size: 10px;
                font-weight: bold;
            }
            """

        report_html = f"""
            <div class="report-number">
                Report No: {context_data["report_number"]}
            </div>
            """

        rendered_html += report_html

        # Generate PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
            temp_path = temp_pdf.name

        HTML(string=rendered_html).write_pdf(
            target=temp_path,
            stylesheets=[CSS(string=default_css)]
        )

        # Save file
        with open(temp_path, "rb") as f:
            file_content = ContentFile(f.read())

        pdf_filename = f"{template_obj.name}_entry_{sample_id}.pdf"
        pdf_path = default_storage.save(f"reports/{pdf_filename}", file_content)
        pdf_url = default_storage.url(pdf_path)

        os.remove(temp_path)

        report.pdf_url = pdf_url
        report.save(update_fields=["pdf_url"])

        return pdf_url

    except Exception as e:
        print(f"Report generation failed: {e}")
        return None


import csv


IGNORE_COLUMNS = {
    "#",
    "Sample Set Id",
    "Result Set Id",
    "SampleName",
    "Name",
}
import re
IGNORE_COLUMNS = {
    "#",
    "Sample Set Id",
    "Result Set Id",
    "SampleName",
    "Name",
}


def clean(value):
    if value is None:
        return ""
    return str(value).strip().strip("'").strip('"')


def parse_line(line):
    return [clean(x) for x in re.findall(r"'([^']*)'", line)]


def import_component_summary(file_path):
    """
    Reads Component Summary Blend table dynamically and stores
    each analysis/result as a separate database row.
    """

    with open(file_path, "r", encoding="cp1252") as f:
        rows = [parse_line(line) for line in f if line.strip()]

    header_index = None
    headers = None

    signoff_datetime = None

    # -------------------------------------------------
    # Find first Sign Off date
    # -------------------------------------------------
    for i, row in enumerate(rows):

        if "Full Name" in row and "Date" in row:

            for data_row in rows[i + 1:]:

                if not data_row:
                    continue

                if data_row[0] == "Result Sign Off":
                    break

                if len(data_row) >= 6:

                    date_string = data_row[-1]

                    if date_string:

                        try:
                            date_string = date_string.replace(" +03", "")

                            signoff_datetime = datetime.strptime(
                                date_string,
                                "%m/%d/%Y %I:%M:%S %p",
                            )

                            break

                        except Exception:
                            pass

            break

    # -------------------------------------------------
    # Find Blend header
    # -------------------------------------------------
    for i, row in enumerate(rows):

        if (
            "Sample Set Id" in row
            and "SampleName" in row
            and "Result Set Id" in row
        ):
            header_index = i
            headers = row
            break

    if headers is None:
        raise Exception("Component Summary Blend table not found.")

    analysis_columns = [
        h
        for h in headers
        if h and h not in IGNORE_COLUMNS
    ]

    print("Detected Analyses:", analysis_columns)

    data_start = header_index + 2

    for row in rows[data_start:]:

        if not row:
            continue

        first = row[0]

        if first in {
            "Min",
            "Max",
            "Mean",
            "% RSD",
            "Result Sign Off",
        }:
            break

        if not first.isdigit():
            continue

        if len(row) > len(headers):
            row = row[: len(headers)]

        if len(row) < len(headers):
            row.extend([""] * (len(headers) - len(row)))

        data = dict(zip(headers, row))

        sample_id = data.get("Sample Set Id", "")
        product_name = data.get("SampleName", "")

        for analysis in analysis_columns:

            result = data.get(analysis, "").strip()

            if result == "":
                continue

            models.SampleAnalysisResult.objects.create(
                sample_id=sample_id,
                product_name=product_name,
                analysis_name=analysis,
                result=result,
                unit=None,
                time=signoff_datetime,
            )

    print("Import Completed.")




IGNORE_POUCH_COLUMNS = {
    "Pouch Number",
    "Status",
    "Processing Start Time",
    "Processing End Time",
}


def clean_pouch(value):
    if value is None:
        return ""
    return str(value).strip().strip('"').strip("'")


def import_pouch_report(file_path):
    """
    Import pouch report.
    Stores only Mean values for each analysis.
    """

    # -------------------------------------
    # Detect delimiter automatically
    # -------------------------------------
    with open(file_path, "r", encoding="cp1252", newline="") as f:

        sample = f.read(4096)
        f.seek(0)

        try:
            dialect = csv.Sniffer().sniff(
                sample,
                delimiters=",;\t",
            )
        except csv.Error:
            dialect = csv.excel

        rows = list(csv.reader(f, dialect))

    print("First 10 rows:")
    for i, row in enumerate(rows[:10]):
        print(i, row)

    sample_id = None
    product_name = None
    processed_time = None

    header_index = None
    headers = None

    # -------------------------------------
    # Read report metadata
    # -------------------------------------
    for i, row in enumerate(rows):

        row = [clean_pouch(x) for x in row]

        if row and row[0] == "Sample ID":

            if i + 1 < len(rows):

                values = [clean_pouch(x) for x in rows[i + 1]]

                if len(values) > 0:
                    sample_id = values[0]

                if len(values) > 4:
                    product_name = values[4]

                if len(values) > 8:
                    processed_time = values[8]

        if "Pouch Number" in row:
            header_index = i
            headers = row
            break

    if header_index is None:
        raise Exception("Pouch table not found.")

    analysis_columns = [
        h for h in headers
        if h and h not in IGNORE_POUCH_COLUMNS
    ]

    print("Detected Analyses:", analysis_columns)

    processed_datetime = None

    if processed_time:
        try:
            processed_datetime = datetime.strptime(
                processed_time,
                "%d/%m/%Y %H:%M:%S",
            )
        except Exception:
            pass

    # -------------------------------------
    # Find Mean row
    # -------------------------------------
    mean_row = None

    for row in rows[header_index + 1:]:

        row = [clean_pouch(x) for x in row]

        if len(row) < len(headers):
            row.extend([""] * (len(headers) - len(row)))

        # Mean row has "Mean" in column index 3
        if len(row) > 3 and row[3].strip().lower() == "mean":
            mean_row = dict(zip(headers, row))
            break

    if mean_row is None:
        raise Exception("Mean row not found.")

    # -------------------------------------
    # Save one record per analysis
    # -------------------------------------
    for analysis in analysis_columns:

        value = mean_row.get(analysis)

        if value in ("", None):
            continue

        models.SampleAnalysisResult.objects.create(
            sample_id=sample_id,
            product_name=product_name,
            analysis_name=analysis,
            result=value,
            unit=None,
            time=processed_datetime,
        )

    print("Pouch Report Imported Successfully.")


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





def generate_qc_label(request, sample_id, inspection):
    try:
        sample = models.DynamicFormEntry.objects.get(id=sample_id)

        logo_path = os.path.join(
            settings.BASE_DIR,
            "static",
            "images",
            "badciel.png"
        )

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>

        <style>

        @page {{
            size:A4;
            margin:15mm;
        }}

        body {{
            font-family: Arial, Helvetica, sans-serif;
            border:4px solid black;
            padding:25px;
            height:95%;
            position:relative;
        }}

        .header {{
            display:flex;
            align-items:center;
        }}

        .logo {{
            width:120px;
        }}

        .title {{
            flex:1;
            text-align:center;
            font-size:34px;
            font-weight:bold;
            margin-right:100px;
        }}

        .field {{
            border:2px solid black;
            margin-top:30px;
            padding:8px;
            font-size:22px;
        }}

        .field-small {{
            width:80%;
        }}

        .footer {{
            position:absolute;
            bottom:30px;
            right:30px;
            border:2px solid black;
            padding:8px 18px;
            font-size:20px;
        }}

        </style>

        </head>

        <body>

        <div class="header">

            <img src="file://{logo_path}" class="logo">

            <div class="title">
                QC SAMPLED
            </div>

        </div>

        <div class="field">
            Materials name :
            <b>{inspection.material.name if inspection.material else ""}</b>
        </div>

        <div class="field">
            Batch Number :
            <b>{inspection.vendor_lot_number or ""}</b>
        </div>

        <div class="field">
            Container No :
            <b>{inspection.number_of_containers_to_be_opened or ""}</b>
        </div>

        <div class="field">
            Sampled Quantity :
            <b>{inspection.sampled_quantity or ""}</b>
        </div>

        <div class="field">
            Sampled By :
            <b>{inspection.sampled_by or inspection.checked_by or ""}</b>
        </div>

        <div class="field field-small">
            Sign / Date :
            <b>{inspection.checked_sign_date or ""}</b>
        </div>

        <div class="footer">
            BC-GRC-IMS-SOP-25-F-07
        </div>

        </body>

        </html>
        """

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as pdf:
            temp_path = pdf.name

        HTML(
            string=html,
            base_url=request.build_absolute_uri("/")
        ).write_pdf(
            target=temp_path
        )

        filename = (
            f"QC_LABEL_{inspection.inspection_sheet_no}.pdf"
        )

        with open(temp_path, "rb") as f:
            pdf_path = default_storage.save(
                f"qc_labels/{filename}",
                ContentFile(f.read())
            )

        pdf_url = default_storage.url(pdf_path)

        os.remove(temp_path)

        return pdf_url

    except Exception:
        traceback.print_exc()
        raise



def process_inspection( inspection, request):
        """
        Create sample and IMS report if decision is accepted/partial.
        Safe to call multiple times.
        """

        if inspection.decision not in ["accepted", "partial"]:
            return

        sample_id = create_sample_from_inspection(
            inspection,
            request.user
        )

        if sample_id:
            if not inspection.qc_label_url:
                pdf_url = generate_qc_label(
                    request,
                    sample_id,
                    inspection
                )

                inspection.qc_label_url = pdf_url
                inspection.save(update_fields=["qc_label_url"])

        return sample_id

        # generated_report_url = None

        # if sample_id:
        #     report = generate_ims_report(request, sample_id)

        #     if report:
        #         generated_report_url = report.pdf_url

        #         inspection.generated_report_url = generated_report_url
        #         inspection.save(update_fields=["generated_report_url"])

            # TODO
            # generate sample label
            # generate inspection label

        # return sample_id


def create_sample_from_inspection(inspection, user):
    try:

        existing_entry = models.DynamicFormEntry.objects.filter(
            inspection=inspection
        ).first()

        if existing_entry:
            return existing_entry.id

        sample_form = models.SampleForm.objects.filter(
            sample_name__icontains="DZRT"
        ).values("id", "sample_name")

        entry = models.DynamicFormEntry.objects.create(
            form=sample_form,
            data={},
            logged_by=user,
            inspection=inspection
        )

        clean_data = {}
        auto_analysis_ids = set()

        product = inspection.material
        product_id = product.id if product else None

        today = timezone.now().date()
        expiry = today + timedelta(days=30)

        for field in sample_form.fields.all():

            name = field.field_name.strip().lower()

            if (
                field.field_property == "link_to_table"
                and field.link_to_table == "app_product"
            ):

                clean_data[field.field_name] = product_id

                if product_id:
                    analysis_ids = (
                        models.ProductSamplingGradeAnalysis.objects
                        .filter(
                            product_sampling_grade__product_id=product_id
                        )
                        .values_list("analysis_id", flat=True)
                        .distinct()
                    )

                    auto_analysis_ids.update(analysis_ids)

            elif name == "product type":
                clean_data[field.field_name] = inspection.material_type

            elif name == "batch number":
                clean_data[field.field_name] = inspection.vendor_lot_number

            elif name == "manufacturing date":
                clean_data[field.field_name] = None

            elif name == "expiry date":
                clean_data[field.field_name] = None

            else:
                clean_data[field.field_name] = None

        entry.data = clean_data
        entry.save()

        if auto_analysis_ids:
            entry.analyses.set(
                models.Analysis.objects.filter(
                    id__in=auto_analysis_ids
                )
            )

            create_entry_analyses(
                entry,
                auto_analysis_ids,
                product_id
            )

        return entry.id

    except Exception:
        traceback.print_exc()
        raise

def generate_ims_report( request, sample_id):
    try:
        sample = models.DynamicFormEntry.objects.get(id=sample_id)

        # IMS Template
        template = models.QueryReportTemplate.objects.get(
            name__iexact="ims"
        )

        # Execute SQL
        result = execute_query(
            template.sql_query,
            {"sample_id": int(sample_id)}
        )

        if not result:
            raise Exception("No data returned from SQL.")

        parsed_data = {}

        if "data" in result[0]:
            try:
                parsed_data = json.loads(result[0]["data"])
            except Exception:
                parsed_data = {}

        report = models.GeneratedReport.objects.create(
            sample=sample,
            template=template
        )

        context = {
            "rows": result,
            "entry": sample,
            "data": parsed_data,
            "sample_text_id": sample.sample_text_id,
            "created_at": sample.created_at,
            "report_number": report.id,
        }

        # QR Code
        qr_url = (
            f"{settings.FRONTEND_BASE_URL}/sample-details/{sample_id}"
        )

        qr = qrcode.QRCode(box_size=3, border=1)
        qr.add_data(qr_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        buffer = BytesIO()
        img.save(buffer, format="PNG")

        context["qr_code"] = (
            "data:image/png;base64,"
            + base64.b64encode(buffer.getvalue()).decode()
        )

        context["sample_url"] = qr_url

        rendered_html = JinjaTemplate(
            template.jinja_html_content
        ).render(context)

        default_css = """
        @page { size:A4; margin:10mm; }

        body{
            font-family:Arial,sans-serif;
        }

        table{
            width:100%;
            border-collapse:collapse;
        }

        th,td{
            border:1px solid black;
            padding:6px;
            font-size:12px;
        }

        .qr-footer{
            position:fixed;
            bottom:0;
            right:0;
        }

        .qr-footer img{
            width:35px;
            height:35px;
        }

        .report-number{
            position: fixed;
            top: 5px;
            right: 5px;
            font-size: 10px;
            font-weight: bold;
        }
        """

        css = default_css + (template.css_content or "")

        rendered_html += f"""
            <div class="report-number">
                Report No: {context["report_number"]}
            </div>

            <div class="qr-footer">
                <img src="{context['qr_code']}">
            </div>
            """

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".pdf"
        ) as temp_pdf:

            temp_path = temp_pdf.name

        HTML(
            string=rendered_html,
            base_url=request.build_absolute_uri("/")
        ).write_pdf(
            target=temp_path,
            stylesheets=[CSS(string=css)]
        )

        filename = f"IMS_{sample.sample_text_id}.pdf"

        with open(temp_path, "rb") as f:
            pdf_path = default_storage.save(
                f"reports/{filename}",
                ContentFile(f.read())
            )

        pdf_url = default_storage.url(pdf_path)

        os.remove(temp_path)

        report.pdf_url = pdf_url
        report.save(update_fields=["pdf_url"])

        return report

    except Exception:
        traceback.print_exc()
        raise

def execute_query(sql_query, params):
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute(sql_query, params)
        columns = [col[0] for col in cursor.description]
        rows = [
            dict(zip(columns, row))
            for row in cursor.fetchall()
        ]

    return rows





