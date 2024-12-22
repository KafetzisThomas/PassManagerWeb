from django.utils.deprecation import MiddlewareMixin


class SessionTimeoutMiddleware(MiddlewareMixin):
    """
    Set session timeout based on the user's choice.
    """

    def process_request(self, request):
        if request.user.is_authenticated:
            session_timeout = request.user.session_timeout
            request.session.set_expiry(session_timeout)
