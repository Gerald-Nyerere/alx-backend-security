from .models import RequestLog, BlockedIP
from ipgeolocation import IPGeolocationAPI
from django.core.cache import cache
from django.http import HttpResponseForbidden

class RequestLogMiddleware: 
    """
    Middleware that logs each request's IP address, timestamp, and path.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = IPGeolocationAPI()

    def __call__(self, request):
        ip = self.get_client_ip(request)
        path = request.path

        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: Your IP has been blocked.")
        
        cache_key = f"geo_{ip}"
        geo_data = cache.get(cache_key)
        
        if not geo_data:
            try:
                geo_data = self.geo.get_geolocation_data(ip)
                cache.set(cache_key, geo_data, 60 * 60 * 24)  # cache for 24 hours
            except Exception:
                geo_data = {}

        country = geo_data.get("country_name") if geo_data else None
        city = geo_data.get("city") if geo_data else None


        if not path.startswith('/admin'):
            RequestLog.objects.create(
                ip_address=ip,
                path=path,
                country=country,
                city=city
            )

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extracts client IP address from request headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
