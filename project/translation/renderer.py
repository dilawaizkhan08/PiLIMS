from rest_framework.renderers import JSONRenderer

from .utils import translate_json


class ArabicJSONRenderer(JSONRenderer):

    def render(
            self,
            data,
            accepted_media_type=None,
            renderer_context=None
    ):

        request = renderer_context["request"]

        if request.translation_language == "ar":

            data = translate_json(data)

        return super().render(
            data,
            accepted_media_type,
            renderer_context
        )