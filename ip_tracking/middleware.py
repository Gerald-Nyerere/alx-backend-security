from .models import RequestLog
from datetime import datetime

class RequestLogMiddleware:
    """
    Middleware that logs each request's IP address, timestamp, and path.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)
        path = request.path

        if not path.startswith('/admin'):
            RequestLog.objects.create(ip_address=ip, path=path)

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """Extracts client IP address from request headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
