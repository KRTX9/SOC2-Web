"""
Session management utilities for enhanced security and monitoring.
"""
from django.utils import timezone
from datetime import timedelta
from .models import UserSession, SecurityEvent
import logging

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Centralized session management for security operations.
    """
    
    # Configuration
    MAX_CONCURRENT_SESSIONS = 5  # Maximum active sessions per user
    SESSION_TIMEOUT_HOURS = 24  # Auto-logout after inactivity
    ANOMALY_ALERT_THRESHOLD = 70  # Risk score threshold for alerts
    
    @classmethod
    def create_and_track_session(cls, user, request, jwt_jti=''):
        """
        Create a new session and perform security checks.
        
        Returns:
            tuple: (session, should_alert, alert_message)
        """
        # Create session
        session = UserSession.create_session(user, request, jwt_jti)
        
        # Enforce concurrent session limit
        UserSession.enforce_concurrent_session_limit(user, cls.MAX_CONCURRENT_SESSIONS)
        
        # Check if should alert user
        should_alert = False
        alert_message = None
        
        if session.is_anomalous:
            should_alert = True
            alert_message = f"New login detected from {session.city or 'unknown location'} using {session.device_name}"
            
            # Send security alert if high risk
            if session.trust_score < 30:
                from .notifications import send_login_notification
                try:
                    send_login_notification(user, request, new_device=True)
                except Exception as e:
                    logger.error(f"Failed to send login notification: {e}")
        
        return session, should_alert, alert_message
    
    @classmethod
    def cleanup_expired_sessions(cls):
        """
        Clean up expired and inactive sessions.
        Should be run periodically (e.g., via Celery task).
        """
        cutoff_time = timezone.now() - timedelta(hours=cls.SESSION_TIMEOUT_HOURS)
        
        # Find expired sessions
        expired_sessions = UserSession.objects.filter(
            is_active=True,
            last_activity__lt=cutoff_time
        )
        
        count = expired_sessions.count()
        
        # Mark as inactive
        for session in expired_sessions:
            session.revoke(reason='session_timeout')
        
        logger.info(f"Cleaned up {count} expired sessions")
        return count
    
    @classmethod
    def revoke_all_user_sessions(cls, user, except_session_id=None, reason=''):
        """
        Revoke all active sessions for a user.
        Useful for password change, account compromise, etc.
        
        Args:
            user: User model instance
            except_session_id: Session ID to keep active (current session)
            reason: Reason for revocation
        """
        sessions = UserSession.objects.filter(user=user, is_active=True)
        
        if except_session_id:
            sessions = sessions.exclude(id=except_session_id)
        
        count = 0
        for session in sessions:
            session.revoke(reason=reason or 'all_sessions_revoked')
            count += 1
        
        logger.info(f"Revoked {count} sessions for user {user.username}")
        return count
    
    @classmethod
    def get_active_sessions(cls, user):
        """Get all active sessions for a user"""
        return UserSession.objects.filter(
            user=user,
            is_active=True
        ).order_by('-last_activity')
    
    @classmethod
    def get_session_stats(cls, user):
        """Get session statistics for a user"""
        sessions = UserSession.objects.filter(user=user)
        
        return {
            'total_sessions': sessions.count(),
            'active_sessions': sessions.filter(is_active=True).count(),
            'trusted_devices': sessions.filter(is_trusted=True).count(),
            'anomalous_sessions': sessions.filter(is_anomalous=True).count(),
            'unique_devices': sessions.values('device_fingerprint').distinct().count(),
            'unique_locations': sessions.values('country', 'city').distinct().count(),
        }
    
    @classmethod
    def detect_account_takeover_patterns(cls, user):
        """
        Detect patterns that might indicate account takeover.
        
        Returns:
            tuple: (is_suspicious, reasons)
        """
        reasons = []
        
        # Pattern 1: Multiple concurrent sessions from different locations
        active_sessions = cls.get_active_sessions(user)
        locations = set()
        for session in active_sessions:
            if session.country:
                locations.add(session.country)
        
        if len(locations) >= 3:
            reasons.append(f'concurrent_sessions_from_{len(locations)}_countries')
        
        # Pattern 2: Sudden spike in failed login attempts followed by success
        from .models import AuditLog
        recent_time = timezone.now() - timedelta(hours=1)
        failed_logins = AuditLog.objects.filter(
            user=user,
            action='login_failed',
            created_at__gte=recent_time
        ).count()
        
        if failed_logins >= 3:
            reasons.append(f'{failed_logins}_failed_attempts_in_last_hour')
        
        # Pattern 3: Multiple anomalous sessions
        anomalous_count = active_sessions.filter(is_anomalous=True).count()
        if anomalous_count >= 2:
            reasons.append(f'{anomalous_count}_anomalous_sessions')
        
        # Pattern 4: Session from known malicious IP (would need IP reputation service)
        # TODO: Integrate with IP reputation API
        
        is_suspicious = len(reasons) > 0
        
        if is_suspicious:
            # Create security event
            SecurityEvent.create_event(
                event_type='account_takeover',
                severity='critical',
                ip_address=active_sessions.first().ip_address if active_sessions else '0.0.0.0',
                description=f'Potential account takeover detected for {user.username}',
                user=user,
                details={
                    'patterns': reasons,
                    'active_sessions': active_sessions.count(),
                    'locations': list(locations)
                },
                risk_score=90
            )
        
        return is_suspicious, reasons
    
    @classmethod
    def update_session_activity(cls, user, request):
        """
        Update last activity timestamp for current session.
        Called on each authenticated request via middleware.
        """
        from .utils import generate_device_fingerprint
        
        device_fingerprint = generate_device_fingerprint(request)
        
        session = UserSession.objects.filter(
            user=user,
            device_fingerprint=device_fingerprint,
            is_active=True
        ).first()
        
        if session:
            session.last_activity = timezone.now()
            session.save(update_fields=['last_activity'])
