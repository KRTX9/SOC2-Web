from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password, check_password
from django.db import models
from django.utils import timezone
from datetime import timedelta
import secrets
import json


class User(AbstractUser):
    """Extended User model for secure authentication"""
    
    email = models.EmailField(unique=True, db_index=True)
    is_verified = models.BooleanField(default=False, db_index=True)
    
    # MFA Fields
    mfa_enabled = models.BooleanField(default=False, db_index=True)
    mfa_secret = models.CharField(max_length=256, null=True, blank=True)  # Increased for encrypted data
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', 'is_verified']),
            models.Index(fields=['email', 'mfa_enabled']),
        ]
    
    def __str__(self):
        return self.username
    
    def set_mfa_secret(self, plaintext_secret):
        """
        Set MFA secret with encryption
        
        Args:
            plaintext_secret (str): The plaintext MFA secret to encrypt and store
        """
        from .encryption import EncryptionService
        
        if plaintext_secret:
            self.mfa_secret = EncryptionService.encrypt(plaintext_secret)
        else:
            self.mfa_secret = None
    
    def get_mfa_secret(self):
        """
        Get decrypted MFA secret
        
        Returns:
            str: The decrypted MFA secret or None
        """
        from .encryption import EncryptionService
        
        if self.mfa_secret:
            return EncryptionService.decrypt(self.mfa_secret)
        return None


class OTPCode(models.Model):
    """OTP codes for password reset and 2FA - stored as hashes for security"""
    
    PURPOSE_CHOICES = (
        ('password_reset', 'Password Reset'),
        ('email_verification', 'Email Verification'),
        ('two_factor', 'Two Factor Authentication'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otp_codes')
    code = models.CharField(max_length=128)  # Hashed code
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    is_used = models.BooleanField(default=False, db_index=True)
    attempts = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'purpose', 'is_used']),
            models.Index(fields=['expires_at', 'is_used']),
        ]
    
    def __str__(self):
        return f"OTP for {self.user.username} - {self.purpose}"
    
    def is_expired(self):
        """Check if OTP is expired"""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if OTP is valid (not used, not expired, attempts < 3)"""
        return not self.is_used and not self.is_expired() and self.attempts < 3
    
    def verify_code(self, plain_code):
        """Verify a plain OTP code against the stored hash"""
        return check_password(plain_code, self.code)
    
    @staticmethod
    def generate_code():
        """Generate a cryptographically secure random 6-digit OTP code"""
        return ''.join(str(secrets.randbelow(10)) for _ in range(6))
    
    @classmethod
    def create_otp(cls, user, purpose, expiry_minutes=10):
        """Create a new OTP for user and invalidate old ones"""
        # Invalidate old OTPs (bulk update for efficiency)
        cls.objects.filter(user=user, purpose=purpose, is_used=False).update(is_used=True)
        
        # Generate new OTP
        plain_code = cls.generate_code()
        hashed_code = make_password(plain_code)
        expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
        
        # Save to database
        otp = cls.objects.create(
            user=user,
            code=hashed_code,
            purpose=purpose,
            expires_at=expires_at
        )
        
        # Attach plain code for email sending
        otp.plain_code = plain_code
        return otp


class AuditLog(models.Model):
    """
    Comprehensive audit log for all authentication and security events.
    Essential for compliance (SOC2, ISO 27001, HIPAA) and incident response.
    """
    
    ACTION_CHOICES = (
        # Authentication Events
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('logout', 'Logout'),
        ('register', 'User Registration'),
        ('token_refresh', 'Token Refresh'),
        
        # Email Verification
        ('email_verify_success', 'Email Verification Success'),
        ('email_verify_failed', 'Email Verification Failed'),
        ('email_resend', 'Email Verification Resent'),
        
        # Password Management
        ('password_change', 'Password Changed'),
        ('password_reset_request', 'Password Reset Requested'),
        ('password_reset_success', 'Password Reset Success'),
        ('password_reset_failed', 'Password Reset Failed'),
        
        # MFA Events
        ('mfa_enabled', 'MFA Enabled'),
        ('mfa_disabled', 'MFA Disabled'),
        ('mfa_verify_success', 'MFA Verification Success'),
        ('mfa_verify_failed', 'MFA Verification Failed'),
        ('mfa_backup_generated', 'MFA Backup Codes Generated'),
        ('mfa_backup_used', 'MFA Backup Code Used'),
        
        # OAuth Events
        ('google_login_success', 'Google Login Success'),
        ('google_login_failed', 'Google Login Failed'),
        
        # Account Security
        ('account_locked', 'Account Locked'),
        ('account_unlocked', 'Account Unlocked'),
        ('session_terminated', 'Session Terminated'),
        ('suspicious_activity', 'Suspicious Activity Detected'),
        
        # Data Access (GDPR)
        ('data_exported', 'Data Exported'),
        ('data_deleted', 'Data Deleted'),
        ('consent_given', 'Consent Given'),
        ('consent_revoked', 'Consent Revoked'),
    )
    
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='audit_logs',
        help_text='User who performed the action (null if system action)'
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES, db_index=True)
    success = models.BooleanField(default=True, db_index=True)
    
    # Request Information
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField(blank=True)
    request_method = models.CharField(max_length=10, default='POST')
    request_path = models.CharField(max_length=255, blank=True)
    
    # Geographic Information
    country = models.CharField(max_length=2, blank=True, help_text='ISO country code')
    city = models.CharField(max_length=100, blank=True)
    
    # Device Information
    device_type = models.CharField(max_length=50, blank=True)  # mobile, desktop, tablet
    device_fingerprint = models.CharField(max_length=64, blank=True, db_index=True)
    
    # Additional Context
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text='Additional context (error messages, risk score, etc.)'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'action', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
            models.Index(fields=['success', '-created_at']),
            models.Index(fields=['action', 'success', '-created_at']),
            # Additional composite indexes for dashboard queries
            models.Index(fields=['action', '-created_at']),  # Action-based filtering
            models.Index(fields=['user', 'success', '-created_at']),  # User success rate
        ]
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
    
    def __str__(self):
        user_str = self.user.username if self.user else 'Anonymous'
        return f"{user_str} - {self.get_action_display()} - {self.created_at}"
    
    @classmethod
    def log(cls, action, user=None, ip_address='0.0.0.0', user_agent='', 
            success=True, metadata=None, request=None):
        """
        Convenience method to create audit log entries.
        
        Usage:
            AuditLog.log('login_success', user=user, ip_address=ip, success=True)
        """
        from .utils import get_client_ip, parse_user_agent
        
        # Extract info from request if provided
        if request:
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            request_method = request.method
            request_path = request.path
        else:
            request_method = 'UNKNOWN'
            request_path = ''
        
        # Parse user agent
        device_info = parse_user_agent(user_agent) if user_agent else {}
        
        return cls.objects.create(
            user=user,
            action=action,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent[:500],  # Truncate long user agents
            request_method=request_method,
            request_path=request_path,
            device_type=device_info.get('device_type', ''),
            metadata=metadata or {},
        )


class SecurityEvent(models.Model):
    """
    High-level security events and threats for monitoring and alerting.
    Aggregates patterns from AuditLog to detect attacks and anomalies.
    """
    
    SEVERITY_CHOICES = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    )
    
    EVENT_TYPE_CHOICES = (
        ('brute_force', 'Brute Force Attack'),
        ('account_takeover', 'Account Takeover Attempt'),
        ('suspicious_login', 'Suspicious Login'),
        ('impossible_travel', 'Impossible Travel'),
        ('multiple_failures', 'Multiple Failed Attempts'),
        ('new_device', 'New Device Login'),
        ('location_anomaly', 'Location Anomaly'),
        ('replay_attack', 'Replay Attack Detected'),
        ('rate_limit_exceeded', 'Rate Limit Exceeded'),
        ('sql_injection', 'SQL Injection Attempt'),
        ('xss_attempt', 'XSS Attempt'),
        ('csrf_attack', 'CSRF Attack'),
        ('enumeration_attempt', 'User Enumeration Attempt'),
        ('credential_stuffing', 'Credential Stuffing'),
        ('session_hijacking', 'Session Hijacking Attempt'),
    )
    
    STATUS_CHOICES = (
        ('detected', 'Detected'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    )
    
    event_type = models.CharField(max_length=50, choices=EVENT_TYPE_CHOICES, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='detected', db_index=True)
    
    # Related User/IP
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_events'
    )
    ip_address = models.GenericIPAddressField(db_index=True)
    
    # Event Details
    description = models.TextField()
    details = models.JSONField(
        default=dict,
        help_text='Detailed information about the event'
    )
    
    # Risk Score (0-100)
    risk_score = models.IntegerField(default=0, help_text='Risk score from 0 to 100')
    
    # Related Audit Logs
    related_logs = models.ManyToManyField(
        AuditLog,
        blank=True,
        related_name='security_events'
    )
    
    # Alert Status
    alert_sent = models.BooleanField(default=False)
    alert_sent_at = models.DateTimeField(null=True, blank=True)
    
    # Resolution
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_security_events'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['severity', 'status', '-created_at']),
            models.Index(fields=['event_type', '-created_at']),
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
            # Additional composite indexes for security dashboard
            models.Index(fields=['user', 'status', '-created_at']),  # User events by status
            models.Index(fields=['severity', '-created_at']),  # Severity filtering
            models.Index(fields=['status', '-created_at']),  # Status filtering
        ]
        verbose_name = 'Security Event'
        verbose_name_plural = 'Security Events'
    
    def __str__(self):
        return f"{self.get_severity_display()} - {self.get_event_type_display()} - {self.created_at}"
    
    def mark_resolved(self, user, notes=''):
        """Mark security event as resolved"""
        self.status = 'resolved'
        self.resolved_by = user
        self.resolved_at = timezone.now()
        self.resolution_notes = notes
        self.save(update_fields=['status', 'resolved_by', 'resolved_at', 'resolution_notes', 'updated_at'])
    
    @classmethod
    def create_event(cls, event_type, severity, ip_address, description, 
                     user=None, details=None, risk_score=0):
        """
        Create a security event and optionally send alerts.
        
        Usage:
            SecurityEvent.create_event(
                'brute_force', 
                'high', 
                '192.168.1.1',
                'Multiple failed login attempts detected',
                user=user,
                risk_score=85
            )
        """
        event = cls.objects.create(
            event_type=event_type,
            severity=severity,
            ip_address=ip_address,
            description=description,
            user=user,
            details=details or {},
            risk_score=risk_score
        )
        
        # Send alerts for high/critical events
        if severity in ['high', 'critical']:
            from .notifications import send_security_alert
            send_security_alert(event)
        
        return event


class MFABackupCode(models.Model):
    """
    Backup recovery codes for MFA.
    Generated when user enables MFA, used if primary MFA device is unavailable.
    """
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_backup_codes')
    code_hash = models.CharField(max_length=128, help_text='Hashed backup code')
    
    # Status
    is_used = models.BooleanField(default=False, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    used_from_ip = models.GenericIPAddressField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_used']),
        ]
        verbose_name = 'MFA Backup Code'
        verbose_name_plural = 'MFA Backup Codes'
    
    def __str__(self):
        status = "Used" if self.is_used else "Active"
        return f"Backup code for {self.user.username} - {status}"
    
    def verify_code(self, plain_code):
        """Verify a plain backup code against the stored hash"""
        return check_password(plain_code, self.code_hash)
    
    def mark_used(self, ip_address='0.0.0.0'):
        """Mark backup code as used"""
        self.is_used = True
        self.used_at = timezone.now()
        self.used_from_ip = ip_address
        self.save(update_fields=['is_used', 'used_at', 'used_from_ip'])
    
    @staticmethod
    def generate_code():
        """Generate a cryptographically secure 8-character alphanumeric backup code"""
        import string
        chars = string.ascii_uppercase + string.digits
        # Remove ambiguous characters: 0, O, 1, I, L
        chars = chars.replace('0', '').replace('O', '').replace('1', '').replace('I', '').replace('L', '')
        return ''.join(secrets.choice(chars) for _ in range(8))
    
    @classmethod
    def generate_codes_for_user(cls, user, count=10):
        """
        Generate backup codes for a user and return plain codes.
        Called when user enables MFA.
        
        Returns: List of plain codes (to be shown to user once)
        """
        # Invalidate all existing backup codes
        cls.objects.filter(user=user).delete()
        
        plain_codes = []
        for _ in range(count):
            plain_code = cls.generate_code()
            hashed_code = make_password(plain_code)
            
            cls.objects.create(
                user=user,
                code_hash=hashed_code
            )
            
            plain_codes.append(plain_code)
        
        # Log the generation
        AuditLog.log(
            'mfa_backup_generated',
            user=user,
            metadata={'codes_count': count}
        )
        
        return plain_codes



class UserSession(models.Model):
    """
    Track user sessions for security monitoring and session management.
    Enables features like concurrent session limits, session revocation, and anomaly detection.
    """
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    
    # Session Identification
    session_key = models.CharField(max_length=40, unique=True, db_index=True, help_text='Django session key')
    jwt_jti = models.CharField(max_length=255, blank=True, db_index=True, help_text='JWT token ID')
    
    # Device Information
    device_fingerprint = models.CharField(max_length=64, db_index=True)
    device_name = models.CharField(max_length=255, blank=True, help_text='Friendly device name (e.g., Chrome on Windows)')
    device_type = models.CharField(max_length=50, blank=True)  # mobile, desktop, tablet
    
    # Browser Information
    browser = models.CharField(max_length=100, blank=True)
    browser_version = models.CharField(max_length=50, blank=True)
    os = models.CharField(max_length=100, blank=True)
    os_version = models.CharField(max_length=50, blank=True)
    
    # Network Information
    ip_address = models.GenericIPAddressField(db_index=True)
    country = models.CharField(max_length=2, blank=True, help_text='ISO country code')
    city = models.CharField(max_length=100, blank=True)
    
    # Trust Level
    is_trusted = models.BooleanField(default=False, help_text='User marked this device as trusted')
    trust_score = models.IntegerField(default=50, help_text='Calculated trust score 0-100')
    
    # Activity Tracking
    login_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True, db_index=True)
    logout_at = models.DateTimeField(null=True, blank=True)
    
    # Session Status
    is_active = models.BooleanField(default=True, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=255, blank=True)
    
    # Anomaly Detection
    is_anomalous = models.BooleanField(default=False, db_index=True)
    anomaly_reasons = models.JSONField(default=list, blank=True)
    
    class Meta:
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user', 'is_active', '-last_activity']),
            models.Index(fields=['user', 'device_fingerprint']),
            models.Index(fields=['ip_address', '-login_at']),
            # Additional indexes for session management
            models.Index(fields=['device_fingerprint', 'is_active']),  # Device lookup
            models.Index(fields=['is_active', '-last_activity']),  # Active sessions cleanup
        ]
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
    
    def __str__(self):
        status = 'Active' if self.is_active else 'Inactive'
        return f"{self.user.username} - {self.device_name or self.device_type} - {status}"
    
    def revoke(self, reason=''):
        """Revoke/terminate this session"""
        self.is_active = False
        self.revoked_at = timezone.now()
        self.revoked_reason = reason
        self.save(update_fields=['is_active', 'revoked_at', 'revoked_reason'])
        
        # Log session termination
        AuditLog.log(
            'session_terminated',
            user=self.user,
            ip_address=self.ip_address,
            metadata={
                'session_id': self.id,
                'reason': reason,
                'device': self.device_name
            }
        )
    
    def mark_trusted(self):
        """Mark this device as trusted"""
        self.is_trusted = True
        self.trust_score = 100
        self.save(update_fields=['is_trusted', 'trust_score'])
    
    def calculate_trust_score(self):
        """
        Calculate trust score based on various factors.
        Returns score 0-100 (higher = more trusted)
        """
        score = 50  # Base score
        
        # Factor 1: Session age (older = more trusted)
        age_days = (timezone.now() - self.login_at).days
        if age_days > 30:
            score += 20
        elif age_days > 7:
            score += 10
        
        # Factor 2: Device seen before
        previous_sessions = UserSession.objects.filter(
            user=self.user,
            device_fingerprint=self.device_fingerprint
        ).exclude(id=self.id).count()
        
        if previous_sessions > 10:
            score += 20
        elif previous_sessions > 3:
            score += 10
        
        # Factor 3: Same IP/location as previous sessions
        same_location_count = UserSession.objects.filter(
            user=self.user,
            country=self.country,
            city=self.city
        ).exclude(id=self.id).count()
        
        if same_location_count > 5:
            score += 10
        
        # Factor 4: No anomalies
        if not self.is_anomalous:
            score += 10
        
        # Factor 5: Manually trusted
        if self.is_trusted:
            score = 100
        
        # Cap at 100
        self.trust_score = min(score, 100)
        self.save(update_fields=['trust_score'])
        return self.trust_score
    
    @classmethod
    def create_session(cls, user, request, jwt_jti=''):
        """
        Create a new session record.
        
        Args:
            user: User model instance
            request: HttpRequest object
            jwt_jti: JWT token ID (optional)
        
        Returns:
            UserSession instance
        """
        from .utils import get_client_ip, parse_user_agent, generate_device_fingerprint
        
        ip_address = get_client_ip(request)
        device_fingerprint = generate_device_fingerprint(request)
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        device_info = parse_user_agent(user_agent_string)
        
        # Generate friendly device name
        device_name = f"{device_info.get('browser', 'Unknown')} on {device_info.get('os', 'Unknown')}"
        
        # Check for existing session with same device fingerprint
        existing_session = cls.objects.filter(
            user=user,
            device_fingerprint=device_fingerprint,
            is_active=True
        ).first()
        
        if existing_session:
            # Update existing session instead of creating new one
            existing_session.last_activity = timezone.now()
            existing_session.jwt_jti = jwt_jti or existing_session.jwt_jti
            existing_session.save(update_fields=['last_activity', 'jwt_jti'])
            return existing_session
        
        # Get or create Django session key
        if not request.session.session_key:
            request.session.create()
        session_key = request.session.session_key
        
        # Check if session_key already exists from a previous session
        # This can happen when user logs out and logs back in with same browser session
        old_session_with_key = cls.objects.filter(session_key=session_key).first()
        if old_session_with_key:
            # Revoke the old session and reuse the session_key
            old_session_with_key.revoke(reason='session_reused')
        
        session = cls.objects.create(
            user=user,
            session_key=session_key,
            jwt_jti=jwt_jti,
            device_fingerprint=device_fingerprint,
            device_name=device_name,
            device_type=device_info.get('device_type', 'unknown'),
            browser=device_info.get('browser', ''),
            browser_version=device_info.get('browser_version', ''),
            os=device_info.get('os', ''),
            os_version=device_info.get('os_version', ''),
            ip_address=ip_address,
        )
        
        # Calculate initial trust score
        session.calculate_trust_score()
        
        # Check for anomalies
        session.detect_anomalies()
        
        return session
    
    def detect_anomalies(self):
        """
        Detect anomalous patterns in this session.
        Sets is_anomalous flag and records reasons.
        """
        anomalies = []
        
        # Anomaly 1: Impossible travel (new location too fast)
        last_session = UserSession.objects.filter(
            user=self.user,
            is_active=True
        ).exclude(id=self.id).order_by('-last_activity').first()
        
        if last_session and last_session.country and self.country:
            if last_session.country != self.country:
                # Different country within short time
                time_diff = (self.login_at - last_session.last_activity).total_seconds() / 3600
                if time_diff < 2:  # Less than 2 hours
                    anomalies.append(f'impossible_travel: {last_session.country} to {self.country} in {time_diff:.1f}h')
        
        # Anomaly 2: New device from new location
        device_seen_before = UserSession.objects.filter(
            user=self.user,
            device_fingerprint=self.device_fingerprint
        ).exclude(id=self.id).exists()
        
        location_seen_before = UserSession.objects.filter(
            user=self.user,
            country=self.country
        ).exclude(id=self.id).exists()
        
        if not device_seen_before and not location_seen_before:
            anomalies.append('new_device_new_location')
        
        # Anomaly 3: Unusual time (if user typically logs in during certain hours)
        # TODO: Implement time-based anomaly detection
        
        # Update anomaly status
        if anomalies:
            self.is_anomalous = True
            self.anomaly_reasons = anomalies
            self.trust_score = max(self.trust_score - 30, 0)
            self.save(update_fields=['is_anomalous', 'anomaly_reasons', 'trust_score'])
            
            # Create security event for high-risk anomalies
            if 'impossible_travel' in str(anomalies):
                SecurityEvent.create_event(
                    event_type='impossible_travel',
                    severity='high',
                    ip_address=self.ip_address,
                    description=f'Impossible travel detected for user {self.user.username}',
                    user=self.user,
                    details={
                        'anomalies': anomalies,
                        'device': self.device_name,
                        'session_id': self.id
                    },
                    risk_score=85
                )
    
    @classmethod
    def enforce_concurrent_session_limit(cls, user, limit=5):
        """
        Enforce maximum concurrent sessions per user.
        Revokes oldest sessions if limit is exceeded.
        
        Args:
            user: User model instance
            limit: Maximum number of concurrent active sessions
        """
        active_sessions = cls.objects.filter(user=user, is_active=True).order_by('-last_activity')
        
        if active_sessions.count() > limit:
            # Revoke oldest sessions
            sessions_to_revoke = active_sessions[limit:]
            for session in sessions_to_revoke:
                session.revoke(reason='concurrent_session_limit_exceeded')
