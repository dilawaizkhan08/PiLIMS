class LanguageMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        language = request.headers.get("Accept-Language", "en")

        if language.lower().startswith("ar"):
            request.translation_language = "ar"
        else:
            request.translation_language = "en"

        return self.get_response(request)