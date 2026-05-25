import json
import requests
from django.conf import settings

def send_discord_signup_alert(user):
    if settings.DEBUG:
        return

    payload = {
        "username": settings.DISCORD_BOT_USERNAME,
        "embeds": [{
            "title": "⏳ Account Pending Approval",
            "color": 16753920,
            "fields": [
                {"name": "User ID", "value": str(user.id), "inline": True},
                {"name": "Email", "value": user.email, "inline": True},
                {"name": "Username", "value": user.username, "inline": True},
                {"name": "Date", "value": user.date_joined.strftime("%d/%m/%Y"), "inline": True},
                {"name": "Status", "value": "🔒 Inactive", "inline": True},
            ]
        }]
    }

    requests.post(
        settings.DISCORD_WEBHOOK_URL,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=5
    )
