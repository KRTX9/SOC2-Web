"""
Security notification system for alerting users and administrators.
"""
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging

logger = logging.getLogger(__name__)


def send_security_alert(security_event):
    """
    Send email alert for high/critical security events.
    
    Args:
        security_event: SecurityEvent model instance
    """
    if not security_event:
        return
    
    # Only send for high/critical events
    if security_event.severity not in ['high', 'critical']:
        return
    
    # Prepare email context
    context = {
        'event': security_event,
        'severity': security_event.get_severity_display(),
        'event_type': security_event.get_event_type_display(),
        'description': security_event.description,
        'ip_address': security_event.ip_address,
        'created_at': security_event.created_at,
        'risk_score': security_event.risk_score,
    }
    
    # Determine recipients
    recipients = []
    
    # Send to affected user if exists
    if security_event.user and security_event.user.email:
        recipients.append(security_event.user.email)
    
    # Send to security team (configure in settings)
    security_team_email = getattr(settings, 'SECURITY_TEAM_EMAIL', None)
    if security_team_email:
        recipients.append(security_team_email)
    
    if not recipients:
        logger.debug(f"No recipients for security alert: {security_event}")
        return
    
    # Prepare email
    subject = f"🚨 Security Alert: {security_event.get_event_type_display()}"
    
    # For now, use plain text. Can create HTML template later
    message = f"""
Security Alert - {security_event.get_severity_display().upper()}

Event Type: {security_event.get_event_type_display()}
Description: {security_event.description}
Risk Score: {security_event.risk_score}/100

Details:
- IP Address: {security_event.ip_address}
- Time: {security_event.created_at}
- Status: {security_event.get_status_display()}

{f"User: {security_event.user.username} ({security_event.user.email})" if security_event.user else "User: Anonymous"}

Additional Details:
{security_event.details}

---
This is an automated security alert from SecureAuth.
If you did not perform this action, please contact support immediately.
    """.strip()
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipients,
            fail_silently=False,
        )
        
        # Mark alert as sent
        from django.utils import timezone
        security_event.alert_sent = True
        security_event.alert_sent_at = timezone.now()
        security_event.save(update_fields=['alert_sent', 'alert_sent_at'])
        
        logger.info(f"Security alert sent for event {security_event.id}")
        
    except Exception as e:
        logger.error(f"Failed to send security alert: {e}")


def send_login_notification(user, request, new_device=False):
    """
    Send notification to user about new login.
    Useful for detecting unauthorized access.
    
    Args:
        user: User model instance
        request: HttpRequest object
        new_device: Boolean indicating if this is a new device
    """
    from .utils import get_client_ip, parse_user_agent
    
    if not user or not user.email:
        return
    
    ip_address = get_client_ip(request)
    user_agent_string = request.META.get('HTTP_USER_AGENT', '')
    device_info = parse_user_agent(user_agent_string)
    
    context = {
        'user': user,
        'ip_address': ip_address,
        'device_type': device_info.get('device_type', 'Unknown'),
        'browser': device_info.get('browser', 'Unknown'),
        'os': device_info.get('os', 'Unknown'),
        'new_device': new_device,
        'timestamp': request._audit_timestamp if hasattr(request, '_audit_timestamp') else None,
    }
    
    subject = "🔐 New login to your SecureAuth account"
    if new_device:
        subject = "🆕 New device login detected"
    
    message = f"""
Hello {user.username},

We detected a {"new" if new_device else "recent"} login to your account:

Device: {device_info.get('device_type', 'Unknown')} - {device_info.get('browser', 'Unknown')} on {device_info.get('os', 'Unknown')}
IP Address: {ip_address}
Time: {context.get('timestamp', 'Just now')}

If this was you, you can ignore this email.

If you don't recognize this activity, please:
1. Change your password immediately
2. Enable two-factor authentication if you haven't already
3. Contact support at support@secureauth.com

---
SecureAuth Security Team
    """.strip()
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True,  # Don't block login if email fails
        )
        logger.info(f"Login notification sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send login notification: {e}")


def send_account_change_notification(user, change_type, request):
    """
    Send notification for critical account changes.
    
    Args:
        user: User model instance
        change_type: Type of change ('password', 'email', 'mfa_enabled', 'mfa_disabled')
        request: HttpRequest object
    """
    from .utils import get_client_ip
    
    if not user or not user.email:
        return
    
    change_messages = {
        'password': 'Your password was changed',
        'email': 'Your email address was changed',
        'mfa_enabled': 'Two-factor authentication was enabled',
        'mfa_disabled': 'Two-factor authentication was disabled',
    }
    
    subject = f"🔒 {change_messages.get(change_type, 'Account change')} - SecureAuth"
    
    ip_address = get_client_ip(request)
    
    message = f"""
Hello {user.username},

This is to confirm that {change_messages.get(change_type, 'a change was made to your account')}.

Change made from:
IP Address: {ip_address}
Time: Just now

If you did not make this change, please:
1. Contact support immediately at support@secureauth.com
2. Change your password
3. Review your recent account activity

---
SecureAuth Security Team
    """.strip()
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True,
        )
        logger.info(f"Account change notification sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send account change notification: {e}")
