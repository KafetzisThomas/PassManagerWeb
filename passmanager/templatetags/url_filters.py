from urllib.parse import urlparse
from django import template

register = template.Library()


@register.filter
def urlsplit(value, part):
    """
    Extract a specific part from a URL.
    """
    try:
        return getattr(urlparse(value), part)
    except Exception:
        return ""
