
from django.core.mail import send_mail
from project import settings
from rest_framework.response import Response
from rest_framework import status
from smtplib import SMTPException
import logging
from app import models



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


def update_status_with_history(entry, new_status, user):
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
            updated_by=user
        )
