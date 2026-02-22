from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class CustomPageNumberPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 1000
    page_query_param = "page"

    def paginate_queryset(self, queryset, request, view=None):
        if request.query_params.get("all") == "true":
            self.page = None
            return None
        return super().paginate_queryset(queryset, request, view)

    def get_paginated_response(self, data):
        if self.page is None:
            return Response({
                "total_records": len(data),
                "results": data,
            })

        return Response({
            "total_records": self.page.paginator.count,
            "total_pages": self.page.paginator.num_pages,
            "current_page": self.page.number,
            "page_size": self.get_page_size(self.request),
            "next": self.get_next_link(),
            "previous": self.get_previous_link(),
            "results": data,
        })