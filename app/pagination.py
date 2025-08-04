from rest_framework.pagination import PageNumberPagination


class CustomPageNumberPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 1000
    PAGE_PARAMETER = "page"

    def get_paginated_response(self, data):
        response = super().get_paginated_response(data)
        response.data["page"] = self.page.number
        return response
