from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import RequestLog, SuspiciousIP

@shared_task
def detect_suspicious_ips():
    """
    Runs hourly to find IPs that:
    - Made more than 100 requests in the past hour.
    - Accessed sensitive paths like /admin or /login.
    Flags them in SuspiciousIP model.
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    recent_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    ip_counts = {}
    for log in recent_logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

        if "/admin" in log.path or "/login" in log.path:
            SuspiciousIP.objects.get_or_create(
                ip_address=log.ip_address,
                defaults={"reason": f"Accessed sensitive path: {log.path}"}
            )

    for ip, count in ip_counts.items():
        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={"reason": f"Exceeded 100 requests/hour ({count})"}
            )

    return f"Checked {len(ip_counts)} IPs, flagged suspicious ones."
