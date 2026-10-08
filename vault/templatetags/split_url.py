from urllib.parse import urlparse

from django import template

register = template.Library()

@register.filter
def split_url(value: str, part: str) -> str:
    """
    Extract a specific part from a URL.
    """
    try:
        return getattr(urlparse(value), part)
    except (AttributeError, ValueError):
        return ""
