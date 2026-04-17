
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



# paginate queryset generic function
def paginate_queryset(request, view, queryset, serializer_class):
    page = view.paginate_queryset(queryset)
    if page is not None:
        serializer = serializer_class(page, many=True, context={"request": request})
        return view.get_paginated_response(serializer.data)
    serializer = serializer_class(queryset, many=True, context={"request": request})
    return Response(serializer.data)


def create_entry_analyses(entry, analysis_ids):
    from app import models

    for analysis in models.Analysis.objects.filter(id__in=analysis_ids):

        ea, _ = models.DynamicFormEntryAnalysis.objects.get_or_create(
            entry=entry,
            analysis=analysis
        )

        components = analysis.components.all()
        ea.components.set(components)

        # delete old
        models.SampleComponent.objects.filter(entry_analysis=ea).delete()

        old_to_new_map = {}

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
            old_to_new_map[comp.id] = sc

        # clone parameters for calculated components
        for comp in components:
            if not comp.calculated:
                continue

            new_sc = old_to_new_map.get(comp.id)
            if not new_sc:
                continue

            for param in comp.function_parameters.all():
                mapped_sc = old_to_new_map.get(param.mapped_component.id)
                if mapped_sc:
                    models.SampleComponentFunctionParameter.objects.create(
                        sample_component=new_sc,
                        parameter=param.parameter,
                        mapped_sample_component=mapped_sc
                    )


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
