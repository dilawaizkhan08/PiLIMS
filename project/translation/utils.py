from .cache import cached_translate


def translate_json(data):

    if isinstance(data, dict):

        return {
            key: translate_json(value)
            for key, value in data.items()
        }

    elif isinstance(data, list):

        return [
            translate_json(item)
            for item in data
        ]

    elif isinstance(data, str):

        return cached_translate(data)

    return data