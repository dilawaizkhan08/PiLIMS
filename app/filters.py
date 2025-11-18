from rest_framework.filters import BaseFilterBackend
from django.db.models import Q

MAX_DEPTH = 2  # how deep to follow related models

def build_search_q(model, search_term, prefix="", depth=0, visited_models=None):
    if visited_models is None:
        visited_models = set()

    # stop recursion if depth too deep
    if depth > MAX_DEPTH or model in visited_models:
        return Q()

    visited_models.add(model)
    q_objects = Q()

    for field in model._meta.get_fields():
        # skip reverse relations to avoid loops
        if field.auto_created and not field.concrete:
            continue

        # Char/Text fields
        if hasattr(field, "get_internal_type") and field.get_internal_type() in ["CharField", "TextField", "EmailField"]:
            lookup = f"{prefix}__{field.name}__icontains" if prefix else f"{field.name}__icontains"
            q_objects |= Q(**{lookup: search_term})

        # ForeignKey / OneToOne
        if field.one_to_one or field.many_to_one:
            related_model = field.related_model
            related_prefix = f"{prefix}__{field.name}" if prefix else field.name
            q_objects |= build_search_q(related_model, search_term, prefix=related_prefix, depth=depth+1, visited_models=visited_models)

        # ManyToMany
        if field.many_to_many:
            related_model = field.related_model
            related_prefix = f"{prefix}__{field.name}" if prefix else field.name
            q_objects |= build_search_q(related_model, search_term, prefix=related_prefix, depth=depth+1, visited_models=visited_models)

    visited_models.remove(model)
    return q_objects


class GenericSearchFilter(BaseFilterBackend):
    """Generic DRF filter: searches all fields + related fields (safe)"""
    def filter_queryset(self, request, queryset, view):
        search_term = request.query_params.get("search")
        if not search_term:
            return queryset
        q_objects = build_search_q(queryset.model, search_term)
        return queryset.filter(q_objects).distinct()
