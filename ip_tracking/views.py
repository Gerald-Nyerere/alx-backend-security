from django.http import JsonResponse
from ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.views import View

def ratelimit_error(request, exception=None):
    return JsonResponse(
        {"error": "Too many requests. Please slow down."},
        status=429
    )

class LoginView(View):
    @method_decorator(ratelimit(key='user', rate='10/m', method='POST', block=True))
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request):
        data = {"message": "Login successful!"}
        return JsonResponse(data)
