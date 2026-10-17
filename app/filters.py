from rest_framework.filters import BaseFilterBackend
from django.db.models import Q
from app.models import Product, DynamicFormEntry
import json
from django.core.exceptions import FieldDoesNotExist
from django.db.models import Q
from rest_framework.exceptions import ValidationError

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


from datetime import datetime
def get_created_at_search_q(search_term):
    q = Q()

    try:
        dt = datetime.strptime(search_term, "%d-%m-%Y").date()
        q |= Q(created_at__date=dt)
        return q
    except ValueError:
        pass

    # DD-MM
    try:
        dt = datetime.strptime(search_term, "%d-%m")
        q |= Q(
            created_at__day=dt.day,
            created_at__month=dt.month,
        )
    except ValueError:
        pass

    return q


class GenericSearchFilter(BaseFilterBackend):
    def filter_queryset(self, request, queryset, view):
        search_term = request.query_params.get("search")
        if not search_term:
            return queryset

        q_objects = build_search_q(queryset.model, search_term)

        if any(f.name == "data" for f in queryset.model._meta.get_fields()):
            q_objects |= Q(data__icontains=search_term)

        # created_at search
        if any(f.name == "created_at" for f in queryset.model._meta.get_fields()):
            q_objects |= get_created_at_search_q(search_term)

        if queryset.model == DynamicFormEntry:
            product_ids = Product.objects.filter(
                name__icontains=search_term
            ).values_list("id", flat=True)

            if product_ids:
                q_objects |= Q(data__Product__in=product_ids)

        return queryset.filter(q_objects).distinct()


OPERATOR_MAP = {
    "exact": "exact",
    "isequal": "exact",
    "eq": "exact",
    "=": "exact",

    "iexact": "iexact",
    "contains": "contains",
    "icontains": "icontains",
    "startswith": "startswith",
    "istartswith": "istartswith",
    "endswith": "endswith",
    "iendswith": "iendswith",

    "gt": "gt",
    ">": "gt",
    "greater_than": "gt",

    "gte": "gte",
    ">=": "gte",
    "greater_than_or_equal": "gte",

    "lt": "lt",
    "<": "lt",
    "less_than": "lt",

    "lte": "lte",
    "<=": "lte",
    "less_than_or_equal": "lte",

    "in": "in",
    "range": "range",
    "isnull": "isnull",
}


def validate_field_path(model, field_path):
    """
    Validate regular model fields, related fields, and JSONField paths.
    Example:
        status
        product__name
        data__Product
        data__Batch__Number
    """
    if not isinstance(field_path, str) or not field_path:
        raise ValidationError({"search": "A valid field is required."})

    parts = field_path.split("__")

    if any(not part for part in parts):
        raise ValidationError({"search": f"Invalid field path: {field_path}"})

    current_model = model

    for index, part in enumerate(parts):
        try:
            field = current_model._meta.get_field(part)
        except FieldDoesNotExist:
            raise ValidationError({
                "search": f"Invalid field path: {field_path}"
            })

        if field.get_internal_type() == "JSONField":
            # Remaining parts, if any, are keys inside the JSON value.
            return field_path

        if index < len(parts) - 1:
            related_model = getattr(field, "related_model", None)

            if related_model is None:
                raise ValidationError({
                    "search": f"Cannot traverse field: {field_path}"
                })

            current_model = related_model

    return field_path


def build_condition(model, item):
    if not isinstance(item, dict):
        raise ValidationError({
            "search": "Each filter must be an object."
        })

    field = item.get("field")
    operator = item.get("operator", "exact")

    if not isinstance(field, str):
        raise ValidationError({
            "search": "Each filter requires a field."
        })

    if operator not in OPERATOR_MAP:
        raise ValidationError({
            "search": f"Unsupported operator: {operator}"
        })

    if "value" not in item:
        raise ValidationError({
            "search": f"Missing value for field: {field}"
        })

    validate_field_path(model, field)

    lookup_operator = OPERATOR_MAP[operator]
    value = item["value"]

    if lookup_operator == "in":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = [v.strip() for v in value.split(",")]

        if not isinstance(value, list):
            raise ValidationError({
                "search": "'in' requires a list of values."
            })

    if lookup_operator == "range":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                raise ValidationError({
                    "search": "'range' requires two values."
                })

        if not isinstance(value, list) or len(value) != 2:
            raise ValidationError({
                "search": "'range' requires exactly two values."
            })

    if lookup_operator == "isnull":
        if isinstance(value, str):
            normalized = value.lower()

            if normalized not in ("true", "false", "1", "0"):
                raise ValidationError({
                    "search": "'isnull' value must be true or false."
                })

            value = normalized in ("true", "1")

        elif not isinstance(value, bool):
            raise ValidationError({
                "search": "'isnull' value must be a boolean."
            })

    condition = Q(**{
        f"{field}__{lookup_operator}": value
    })

    if operator in ("!=", "ne", "not_equal"):
        condition = ~Q(**{f"{field}__exact": value})

    return condition


class GenericAdvancedSearchFilter(BaseFilterBackend):

    max_filters = 30

    def filter_queryset(self, request, queryset, view):
        raw_search = request.query_params.get("search")

        if not raw_search:
            return queryset

        try:
            payload = json.loads(raw_search)
        except (json.JSONDecodeError, TypeError):
            raise ValidationError({
                "search": (
                    "Invalid JSON. Pass an object containing "
                    "'filters' and optional 'join'."
                )
            })

        if not isinstance(payload, dict):
            raise ValidationError({
                "search": "Search must be a JSON object."
            })

        filters = payload.get("filters", [])
        join = str(payload.get("join", "AND")).upper()

        if join not in ("AND", "OR"):
            raise ValidationError({
                "search": "'join' must be AND or OR."
            })

        if not isinstance(filters, list):
            raise ValidationError({
                "search": "'filters' must be a list."
            })

        if len(filters) > self.max_filters:
            raise ValidationError({
                "search": f"Maximum {self.max_filters} filters allowed."
            })

        if not filters:
            return queryset

        combined_q = Q()

        for index, item in enumerate(filters):
            condition = build_condition(queryset.model, item)

            if index == 0:
                combined_q = condition
            elif join == "AND":
                combined_q &= condition
            else:
                combined_q |= condition

        return queryset.filter(combined_q).distinct()
 
