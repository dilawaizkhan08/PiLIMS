from django.core.cache import cache

def get_cached_translation(text):

    key = f"translation:{text}"

    return cache.get(key)


def save_translation(text, translated):

    key = f"translation:{text}"

    cache.set(
        key,
        translated,
        timeout=86400 * 30
    )


from .translator import translate

def cached_translate(text):

    cached = get_cached_translation(text)

    if cached:
        return cached

    translated = translate(text)

    save_translation(text, translated)

    return translated

