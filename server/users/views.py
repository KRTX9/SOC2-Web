from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from django.contrib.auth import authenticate, get_user_model
from django.middleware.csrf import get_token
from django.core.cache import cache
from django.conf import settings
from django.db import transaction
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
import threading
import secrets as _secrets

from .models import OTPCode, AuditLog, MFABackupCode, SecurityEvent, UserSession
from .session_manager import SessionManager
from .utils import constant_time_response_delay, generate_device_fingerprint, get_client_ip
from .turnstile import verify_turnstile_or_bypass
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,
    PasswordResetRequestSerializer, PasswordResetVerifySerializer,
    PasswordChangeSerializer, MFAVerifySerializer
)
from .authentication import (
    send_verification_email, send_welcome_email,
    LoginRateThrottle, RegisterRateThrottle, 
    PasswordResetRateThrottle, OTPVerificationRateThrottle,
    set_jwt_cookies, clear_jwt_cookies
)

import logging
import pyotp
import qrcode
import base64
from io import BytesIO

logger = logging.getLogger(__name__)

User = get_user_model()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def send_email_async(email_func, *args):
    """Send emails asynchronously to avoid blocking requests"""
    def send_email():
        try:
            email_func(*args)
        except Exception as e:
            logger.error("Email send failed: %s", e)
    
    thread = threading.Thread(target=send_email, daemon=True)
    thread.start()


# ============================================================================
# ACCOUNT LOCKOUT HELPERS
# ============================================================================

# Per-account failed login tracking (supplements IP-based rate limiting)
ACCOUNT_MAX_FAILED_ATTEMPTS = 5
ACCOUNT_LOCKOUT_SECONDS = 900  # 15 minutes


def _check_account_lockout(email):
    """Return (is_locked, remaining_seconds). Uses Django cache."""
    lock_key = f'account_lockout:{email}'
    locked_until = cache.get(lock_key)
    if locked_until:
        return True, ACCOUNT_LOCKOUT_SECONDS
    return False, 0


def _record_failed_login(email):
    """Increment failed counter. Lock account if threshold reached."""
    counter_key = f'login_failures:{email}'
    failures = cache.get(counter_key, 0) + 1
    cache.set(counter_key, failures, timeout=ACCOUNT_LOCKOUT_SECONDS)
    if failures >= ACCOUNT_MAX_FAILED_ATTEMPTS:
        cache.set(f'account_lockout:{email}', True, timeout=ACCOUNT_LOCKOUT_SECONDS)


def _clear_failed_logins(email):
    """Reset counter on successful authentication."""
    cache.delete(f'login_failures:{email}')
    cache.delete(f'account_lockout:{email}')


# ============================================================================
# AUTHENTICATION VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([RegisterRateThrottle])
def register(request):
    """
    Register a new user or resend verification for unverified accounts.
    
    SECURITY: Prevents email enumeration by:
    - Always returning the same response time (constant delay)
    - Not revealing if email already exists
    - Silently handling existing verified accounts
    - CAPTCHA verification to prevent bot registrations
    """
    # Verify Turnstile CAPTCHA token
    turnstile_token = request.data.get('turnstile_token')
    ip_address = get_client_ip(request)
    
    is_valid, error_message = verify_turnstile_or_bypass(turnstile_token, ip_address)
    if not is_valid:
        AuditLog.log(
            'register',
            user=None,
            request=request,
            success=False,
            metadata={'reason': 'captcha_failed', 'error': error_message}
        )
        return Response(
            {'error': error_message},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    email = request.data.get('email')
    username = request.data.get('username')
    
    # Always add timing protection
    constant_time_response_delay()
    
    # Check for existing user with this email
    existing_user = None
    if email:
        existing_user = User.objects.filter(email=email).only('id', 'email', 'username', 'is_verified').first()
    
    # Case 1: Email exists and is verified - Don't reveal this
    if existing_user and existing_user.is_verified:
        # Log suspicious activity (possible enumeration attempt)
        AuditLog.log(
            'register',
            user=None,
            request=request,
            success=False,
            metadata={'reason': 'email_already_exists', 'email': email}
        )
        
        # Return generic error that doesn't reveal email exists
        return Response(
            {'error': 'Unable to complete registration. Please check your information or try logging in.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Case 2: Email exists but unverified - Resend verification
    if existing_user and not existing_user.is_verified:
        # Invalidate old OTP codes
        OTPCode.objects.filter(user=existing_user, purpose='email_verification', is_used=False).update(is_used=True)
        send_email_async(send_verification_email, existing_user)
        
        # Log the resend
        AuditLog.log('email_resend', user=existing_user, request=request, success=True)
        
        # Generate tokens
        refresh = RefreshToken.for_user(existing_user)
        response = Response({
            'message': 'Registration successful. Please check your email to verify your account.',
            'user': UserSerializer(existing_user).data,
        }, status=status.HTTP_201_CREATED)
        
        set_jwt_cookies(response, str(refresh.access_token), str(refresh))
        return response
    
    # Case 3: New user - Validate and create
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        # Log failed registration attempt
        AuditLog.log('register', user=None, request=request, success=False, 
                     metadata={'errors': serializer.errors})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Create user
    try:
        user = serializer.save()
        send_email_async(send_verification_email, user)
        
        # Log successful registration
        AuditLog.log('register', user=user, request=request, success=True)
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        response = Response({
            'message': 'Registration successful. Please check your email to verify your account.',
            'user': UserSerializer(user).data,
        }, status=status.HTTP_201_CREATED)
        
        set_jwt_cookies(response, str(refresh.access_token), str(refresh))
        return response
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        AuditLog.log('register', user=None, request=request, success=False, 
                     metadata={'error': str(e)})
        return Response(
            {'error': 'Unable to complete registration. Please try again.'},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def login(request):
    """
    User login with MFA support and account-level lockout.
    
    SECURITY: Prevents email enumeration via:
    - Constant-time password hashing (even for non-existent users)
    - Identical error messages for wrong email vs wrong password
    - Timing-safe comparison
    - CAPTCHA verification to prevent brute force attacks
    """
    # Verify Turnstile CAPTCHA token
    turnstile_token = request.data.get('turnstile_token')
    ip_address = get_client_ip(request)
    
    is_valid, error_message = verify_turnstile_or_bypass(turnstile_token, ip_address)
    if not is_valid:
        AuditLog.log(
            'login_failed',
            user=None,
            request=request,
            success=False,
            metadata={'reason': 'captcha_failed', 'error': error_message}
        )
        return Response(
            {'error': error_message},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    serializer = LoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    password = serializer.validated_data['password']
    
    # Constant time delay to prevent timing attacks
    constant_time_response_delay()
    
    # Account-level lockout check (supplements IP-based throttle)
    is_locked, _ = _check_account_lockout(email)
    if is_locked:
        # Log lockout attempt
        AuditLog.log('login_failed', user=None, request=request, success=False,
                     metadata={'reason': 'account_locked', 'email': email})
        return Response(
            {'error': 'Account temporarily locked due to too many failed attempts. Try again in 15 minutes.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    
    # Try to find user and authenticate
    user = None
    try:
        user_obj = User.objects.only('id', 'username', 'email', 'is_verified', 'mfa_enabled', 'mfa_secret').get(email=email)
        user = authenticate(username=user_obj.username, password=password)
    except User.DoesNotExist:
        # Mitigate timing oracle: run a dummy hash so response time is
        # indistinguishable from the "wrong password" path.
        User().set_password(password)
        user = None
    
    # Authentication failed
    if not user:
        _record_failed_login(email)
        
        # Log failed attempt
        AuditLog.log('login_failed', user=None, request=request, success=False,
                     metadata={'reason': 'invalid_credentials', 'email': email})
        
        # Generic error message (don't reveal if email exists)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
    # Clear failed login counter
    _clear_failed_logins(email)
    
    # Check if MFA is required
    if user.mfa_enabled and user.get_mfa_secret():
        # Issue a single-use challenge token so MFA step is bound to this password check
        mfa_challenge = _secrets.token_urlsafe(32)
        cache.set(f'mfa_challenge:{mfa_challenge}', user.pk, timeout=300)  # 5 min
        
        # Log MFA challenge issued
        AuditLog.log('login_success', user=user, request=request, success=True,
                     metadata={'mfa_required': True})
        
        return Response({
            'mfa_required': True,
            'mfa_token': mfa_challenge,
            'message': 'Please enter your MFA code from Google Authenticator'
        }, status=status.HTTP_200_OK)
    
    # Successful login (no MFA)
    AuditLog.log('login_success', user=user, request=request, success=True)
    
    # Create and track session
    session, should_alert, alert_message = SessionManager.create_and_track_session(user, request)
    
    # Generate tokens
    refresh = RefreshToken.for_user(user)
    response_data = {'user': UserSerializer(user).data}
    
    # Add security alert if anomalous login
    if should_alert and alert_message:
        response_data['security_alert'] = alert_message
    
    response = Response(response_data)
    set_jwt_cookies(response, str(refresh.access_token), str(refresh))
    
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
def logout(request):
    """User logout with token blacklisting and complete cookie clearing"""
    user = request.user if request.user.is_authenticated else None
    
    # Blacklist the refresh token to prevent reuse
    jwt_settings = settings.SIMPLE_JWT
    refresh_token_cookie = request.COOKIES.get(
        jwt_settings.get('AUTH_COOKIE_REFRESH', 'refresh_token')
    )
    
    if refresh_token_cookie:
        try:
            token = RefreshToken(refresh_token_cookie)
            token.blacklist()
        except (TokenError, InvalidToken):
            pass  # Token already invalid/expired, still clear cookies
    
    # Log logout
    AuditLog.log('logout', user=user, request=request, success=True)
    
    response = Response({'message': 'Logout successful'})
    clear_jwt_cookies(response)
    return response


@api_view(['GET'])
@permission_classes([AllowAny])
def get_csrf_token(request):
    """Get CSRF token for client"""
    csrf_token = get_token(request)
    
    response = Response({'detail': 'CSRF cookie set', 'csrfToken': csrf_token})
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=settings.CSRF_COOKIE_AGE,
        secure=settings.CSRF_COOKIE_SECURE,
        httponly=settings.CSRF_COOKIE_HTTPONLY,
        samesite=settings.CSRF_COOKIE_SAMESITE,
        path='/',
    )
    
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token(request):
    """Refresh access token using refresh token from cookie.
    
    Security: Validates that the user is still active before issuing new tokens.
    A deactivated/banned user cannot silently keep refreshing.
    """
    jwt_settings = settings.SIMPLE_JWT
    refresh_token_cookie = request.COOKIES.get(jwt_settings.get('AUTH_COOKIE_REFRESH', 'refresh_token'))
    
    if not refresh_token_cookie:
        return Response({'error': 'Refresh token not found'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        refresh = RefreshToken(refresh_token_cookie)
        
        # Verify the user still exists and is active
        user_id = refresh.payload.get('user_id')
        try:
            user = User.objects.only('id', 'is_active').get(pk=user_id)
            if not user.is_active:
                refresh.blacklist()
                response = Response({'error': 'Account is deactivated'}, status=status.HTTP_401_UNAUTHORIZED)
                clear_jwt_cookies(response)
                return response
        except User.DoesNotExist:
            response = Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
            clear_jwt_cookies(response)
            return response
        
        access_token = str(refresh.access_token)
        new_refresh_token = str(refresh) if jwt_settings.get('ROTATE_REFRESH_TOKENS', False) else refresh_token_cookie
        
        response = Response({'message': 'Token refreshed successfully'})
        set_jwt_cookies(response, access_token, new_refresh_token)
        
        return response
        
    except (TokenError, InvalidToken):
        return Response({'error': 'Invalid or expired refresh token'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user(request):
    """Get current authenticated user"""
    return Response(UserSerializer(request.user).data)


# ============================================================================
# EMAIL VERIFICATION VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([OTPVerificationRateThrottle])
def verify_email_otp(request):
    """Verify user email with OTP code"""
    email = request.data.get('email')
    code = request.data.get('code')
    
    if not email or not code:
        return Response({'error': 'Email and code are required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Constant time delay
    constant_time_response_delay()
    
    try:
        user = User.objects.only('id', 'email', 'is_verified').get(email=email)
        
        if user.is_verified:
            AuditLog.log('email_verify_failed', user=user, request=request, success=False,
                        metadata={'reason': 'already_verified'})
            return Response({'message': 'Email is already verified'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Atomic block + select_for_update prevents two concurrent requests
        # from both verifying the same OTP before either marks it used.
        with transaction.atomic():
            otps = list(
                OTPCode.objects.select_for_update()
                .filter(user=user, purpose='email_verification', is_used=False)
            )
            valid_otps = [o for o in otps if not o.is_expired() and o.attempts < 3]
            otp = next((o for o in valid_otps if o.verify_code(code)), None)
            
            if not otp:
                for o in valid_otps:
                    o.attempts += 1
                    o.save(update_fields=['attempts'])
                
                # Log failed verification
                AuditLog.log('email_verify_failed', user=user, request=request, success=False,
                            metadata={'reason': 'invalid_code'})
                
                return Response({'error': 'Invalid or expired OTP code'}, status=status.HTTP_400_BAD_REQUEST)
            
            otp.is_used = True
            otp.save(update_fields=['is_used'])
        
        user.is_verified = True
        user.save(update_fields=['is_verified'])
        
        send_email_async(send_welcome_email, user)
        
        # Log successful verification
        AuditLog.log('email_verify_success', user=user, request=request, success=True)
        
        return Response({
            'message': 'Email verified successfully',
            'user': UserSerializer(user).data
        })
    
    except User.DoesNotExist:
        # Don't reveal if email exists
        AuditLog.log('email_verify_failed', user=None, request=request, success=False,
                    metadata={'reason': 'user_not_found', 'email': email})
        return Response({'error': 'Invalid or expired OTP code'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([OTPVerificationRateThrottle])
def resend_verification(request):
    """
    Resend verification OTP.
    
    SECURITY: Prevents user enumeration by always returning success.
    """
    email = request.data.get('email')
    
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Constant time delay
    constant_time_response_delay()
    
    # Silently handle - don't reveal if account exists
    try:
        user = User.objects.only('id', 'email', 'is_verified').get(email=email)
        
        if not user.is_verified:
            OTPCode.objects.filter(user=user, purpose='email_verification', is_used=False).update(is_used=True)
            send_email_async(send_verification_email, user)
            
            # Log resend
            AuditLog.log('email_resend', user=user, request=request, success=True)
    except User.DoesNotExist:
        # Don't reveal whether account exists - just log it
        AuditLog.log('email_resend', user=None, request=request, success=False,
                     metadata={'reason': 'user_not_found', 'email': email})
    
    # Always return same message
    return Response({'message': 'If the account exists and is not verified, a verification email has been sent.'})


# ============================================================================
# PASSWORD MANAGEMENT VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([PasswordResetRateThrottle])
def password_reset_request(request):
    """
    Request password reset OTP.
    
    SECURITY: Prevents user enumeration by:
    - Always returning success message
    - Using constant-time delay
    - Not revealing if email exists in system
    - CAPTCHA verification to prevent automated attacks
    """
    # Verify Turnstile CAPTCHA token
    turnstile_token = request.data.get('turnstile_token')
    ip_address = get_client_ip(request)
    
    is_valid, error_message = verify_turnstile_or_bypass(turnstile_token, ip_address)
    if not is_valid:
        AuditLog.log(
            'password_reset_request',
            user=None,
            request=request,
            success=False,
            metadata={'reason': 'captcha_failed', 'error': error_message}
        )
        return Response(
            {'error': error_message},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    serializer = PasswordResetRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    
    # Constant time delay to prevent timing attacks
    constant_time_response_delay()
    
    # Silently handle - don't reveal if account exists
    try:
        user = User.objects.only('id', 'email').get(email=email)
        
        OTPCode.objects.filter(user=user, purpose='password_reset', is_used=False).update(is_used=True)
        otp = OTPCode.create_otp(user, 'password_reset', expiry_minutes=10)
        
        from .authentication import send_otp_email
        send_email_async(send_otp_email, user, otp.plain_code, 'password_reset')
        
        # Log reset request
        AuditLog.log('password_reset_request', user=user, request=request, success=True)
        
    except User.DoesNotExist:
        # Don't reveal account doesn't exist - just log it
        AuditLog.log('password_reset_request', user=None, request=request, success=False,
                     metadata={'reason': 'user_not_found', 'email': email})
    
    # Always return same message
    return Response({'message': 'If an account exists with this email, an OTP has been sent.', 'email': email})


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([OTPVerificationRateThrottle])
def password_reset_verify(request):
    """Verify OTP and reset password"""
    serializer = PasswordResetVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    otp_code = serializer.validated_data['otp']
    new_password = serializer.validated_data['new_password']
    
    # Constant time delay
    constant_time_response_delay()
    
    try:
        user = User.objects.only('id', 'email', 'password').get(email=email)
        
        # Atomic + select_for_update prevents concurrent OTP replay
        with transaction.atomic():
            otps = list(
                OTPCode.objects.select_for_update()
                .filter(user=user, purpose='password_reset', is_used=False)
            )
            valid_otps = [o for o in otps if not o.is_expired() and o.attempts < 3]
            otp = next((o for o in valid_otps if o.verify_code(otp_code)), None)
            
            if not otp:
                for o in valid_otps:
                    o.attempts += 1
                    o.save(update_fields=['attempts'])
                
                # Log failed attempt
                AuditLog.log('password_reset_failed', user=user, request=request, success=False,
                            metadata={'reason': 'invalid_otp'})
                
                return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
            
            otp.is_used = True
            otp.save(update_fields=['is_used'])
        
        # Update password (outside atomic block — separate concern)
        user.set_password(new_password)
        user.save(update_fields=['password'])
        
        # Invalidate ALL existing sessions — a stolen token must not survive a reset
        tokens = OutstandingToken.objects.filter(user=user)
        for token in tokens:
            BlacklistedToken.objects.get_or_create(token=token)
        
        # Log successful password reset
        AuditLog.log('password_reset_success', user=user, request=request, success=True)
        
        # Send notification
        from .notifications import send_account_change_notification
        send_account_change_notification(user, 'password', request)
        
        return Response({'message': 'Password reset successful'})
    
    except User.DoesNotExist:
        # Don't reveal if user exists
        AuditLog.log('password_reset_failed', user=None, request=request, success=False,
                    metadata={'reason': 'user_not_found', 'email': email})
        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def password_change(request):
    """Change authenticated user's password and invalidate all other sessions."""
    serializer = PasswordChangeSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    user = request.user
    old_password = serializer.validated_data['old_password']
    new_password = serializer.validated_data['new_password']
    
    if not user.check_password(old_password):
        # Log failed attempt
        AuditLog.log('password_change', user=user, request=request, success=False,
                    metadata={'reason': 'incorrect_old_password'})
        return Response({'error': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
    
    user.set_password(new_password)
    user.save(update_fields=['password'])
    
    # Invalidate ALL existing sessions — prevents compromised token reuse
    tokens = OutstandingToken.objects.filter(user=user)
    for token in tokens:
        BlacklistedToken.objects.get_or_create(token=token)
    
    # Log successful password change
    AuditLog.log('password_change', user=user, request=request, success=True)
    
    # Send notification about password change
    from .notifications import send_account_change_notification
    send_account_change_notification(user, 'password', request)
    
    # Issue fresh tokens for the current session
    refresh = RefreshToken.for_user(user)
    response = Response({'message': 'Password changed successfully'})
    set_jwt_cookies(response, str(refresh.access_token), str(refresh))
    return response


# ============================================================================
# MFA (MULTI-FACTOR AUTHENTICATION) VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_setup(request):
    """Setup MFA for user - Generate secret and QR code"""
    user = request.user
    
    if user.mfa_enabled:
        return Response({'error': 'MFA is already enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    secret = pyotp.random_base32()
    user.set_mfa_secret(secret)  # Use encryption method
    user.save(update_fields=['mfa_secret'])
    
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name='SecureAuth')
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return Response({
        'secret': secret,
        'qr_code': f'data:image/png;base64,{img_str}',
        'message': 'Scan the QR code with Google Authenticator app'
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_enable(request):
    """Enable MFA after verifying the code and generate backup codes"""
    user = request.user
    code = request.data.get('code')
    
    if not code:
        return Response({'error': 'Verification code is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    if user.mfa_enabled:
        return Response({'error': 'MFA is already enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    mfa_secret = user.get_mfa_secret()  # Use decryption method
    if not mfa_secret:
        return Response({'error': 'MFA setup not completed. Please call /mfa/setup/ first'}, status=status.HTTP_400_BAD_REQUEST)
    
    totp = pyotp.TOTP(mfa_secret)
    if not totp.verify(code, valid_window=1):
        # Log failed MFA enable attempt
        AuditLog.log('mfa_enabled', user=user, request=request, success=False,
                    metadata={'reason': 'invalid_code'})
        return Response({'error': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Enable MFA
    user.mfa_enabled = True
    user.save(update_fields=['mfa_enabled'])
    
    # Generate backup codes
    backup_codes = MFABackupCode.generate_codes_for_user(user, count=10)
    
    # Log successful MFA enable
    AuditLog.log('mfa_enabled', user=user, request=request, success=True)
    
    # Send notification
    from .notifications import send_account_change_notification
    send_account_change_notification(user, 'mfa_enabled', request)
    
    return Response({
        'message': 'MFA enabled successfully',
        'user': UserSerializer(user).data,
        'backup_codes': backup_codes  # Return once, user must save them
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_disable(request):
    """Disable MFA for user and delete all backup codes"""
    password = request.data.get('password')
    
    if not password:
        return Response({'error': 'Password is required to disable MFA'}, status=status.HTTP_400_BAD_REQUEST)
    
    user = request.user
    
    if not user.check_password(password):
        # Log failed attempt
        AuditLog.log('mfa_disabled', user=user, request=request, success=False,
                    metadata={'reason': 'invalid_password'})
        return Response({'error': 'Invalid password'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Delete all backup codes
    MFABackupCode.objects.filter(user=user).delete()
    
    user.mfa_enabled = False
    user.set_mfa_secret(None)  # Clear encrypted secret
    user.save(update_fields=['mfa_enabled', 'mfa_secret'])
    
    # Log successful MFA disable
    AuditLog.log('mfa_disabled', user=user, request=request, success=True)
    
    # Send notification
    from .notifications import send_account_change_notification
    send_account_change_notification(user, 'mfa_disabled', request)
    
    return Response({'message': 'MFA disabled successfully', 'user': UserSerializer(user).data})


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def mfa_verify_login(request):
    """Verify MFA code during login.
    
    Security: Requires a server-issued mfa_token (from login or Google OAuth)
    that proves the user already passed primary authentication. The token is
    single-use and expires after 5 minutes.
    """
    serializer = MFAVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    mfa_token = serializer.validated_data['mfa_token']
    mfa_code = serializer.validated_data['mfa_code']
    
    # Resolve and consume the challenge token (single-use)
    cache_key = f'mfa_challenge:{mfa_token}'
    user_pk = cache.get(cache_key)
    if not user_pk:
        AuditLog.log('mfa_verify_failed', user=None, request=request, success=False,
                    metadata={'reason': 'invalid_session'})
        return Response({'error': 'Invalid or expired MFA session'}, status=status.HTTP_400_BAD_REQUEST)
    cache.delete(cache_key)  # Single-use: consumed immediately
    
    try:
        user = User.objects.only('id', 'email', 'mfa_enabled', 'mfa_secret').get(pk=user_pk)
        
        if not user.mfa_enabled:
            AuditLog.log('mfa_verify_failed', user=user, request=request, success=False,
                        metadata={'reason': 'mfa_not_enabled'})
            return Response({'error': 'MFA is not enabled for this account'}, status=status.HTTP_400_BAD_REQUEST)
        
        mfa_secret = user.get_mfa_secret()  # Use decryption method
        if not mfa_secret:
            AuditLog.log('mfa_verify_failed', user=user, request=request, success=False,
                        metadata={'reason': 'mfa_secret_missing'})
            return Response({'error': 'MFA is not enabled for this account'}, status=status.HTTP_400_BAD_REQUEST)
        
        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(mfa_code, valid_window=1):
            # Log failed verification
            AuditLog.log('mfa_verify_failed', user=user, request=request, success=False,
                        metadata={'reason': 'invalid_code'})
            return Response({'error': 'Invalid MFA code'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Log successful MFA verification
        AuditLog.log('mfa_verify_success', user=user, request=request, success=True)
        
        # Create and track session
        session, should_alert, alert_message = SessionManager.create_and_track_session(user, request)
        
        # Get backup codes status
        backup_codes_status = None
        if user.mfa_enabled:
            from .models import MFABackupCode
            total_codes = MFABackupCode.objects.filter(user=user).count()
            unused_codes = MFABackupCode.objects.filter(user=user, is_used=False).count()
            
            backup_codes_status = {
                'total': total_codes,
                'unused': unused_codes,
                'warning': unused_codes <= 3 and total_codes > 0
            }
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        response_data = {
            'user': UserSerializer(user).data,
            'message': 'Login successful'
        }
        
        # Add backup codes status if available
        if backup_codes_status:
            response_data['backup_codes_status'] = backup_codes_status
        
        # Add security alert if anomalous
        if should_alert and alert_message:
            response_data['security_alert'] = alert_message
        
        response = Response(response_data)
        set_jwt_cookies(response, str(refresh.access_token), str(refresh))
        
        return response
        
    except User.DoesNotExist:
        AuditLog.log('mfa_verify_failed', user=None, request=request, success=False,
                    metadata={'reason': 'user_not_found'})
        return Response({'error': 'Invalid MFA code'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def mfa_verify_backup_code(request):
    """
    Verify MFA backup code during login.
    Backup codes are single-use and should be used only when primary MFA is unavailable.
    """
    mfa_token = request.data.get('mfa_token')
    backup_code = request.data.get('backup_code')
    
    if not mfa_token or not backup_code:
        return Response({'error': 'MFA token and backup code are required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Resolve and consume the challenge token (single-use)
    cache_key = f'mfa_challenge:{mfa_token}'
    user_pk = cache.get(cache_key)
    if not user_pk:
        AuditLog.log('mfa_backup_used', user=None, request=request, success=False,
                    metadata={'reason': 'invalid_session'})
        return Response({'error': 'Invalid or expired MFA session'}, status=status.HTTP_400_BAD_REQUEST)
    cache.delete(cache_key)  # Single-use: consumed immediately
    
    try:
        user = User.objects.only('id', 'email', 'mfa_enabled').get(pk=user_pk)
        
        if not user.mfa_enabled:
            AuditLog.log('mfa_backup_used', user=user, request=request, success=False,
                        metadata={'reason': 'mfa_not_enabled'})
            return Response({'error': 'MFA is not enabled for this account'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Find and verify backup code (atomic to prevent race conditions)
        from .utils import get_client_ip
        ip_address = get_client_ip(request)
        
        with transaction.atomic():
            # Get all unused backup codes for user
            backup_codes = list(
                MFABackupCode.objects.select_for_update()
                .filter(user=user, is_used=False)
            )
            
            # Try to find matching code
            valid_code = None
            for bc in backup_codes:
                if bc.verify_code(backup_code):
                    valid_code = bc
                    break
            
            if not valid_code:
                # Log failed attempt
                AuditLog.log('mfa_backup_used', user=user, request=request, success=False,
                            metadata={'reason': 'invalid_code'})
                return Response({'error': 'Invalid backup code'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Mark code as used
            valid_code.mark_used(ip_address)
        
        # Count remaining backup codes
        remaining_codes = MFABackupCode.objects.filter(user=user, is_used=False).count()
        
        # Log successful backup code usage
        AuditLog.log('mfa_backup_used', user=user, request=request, success=True,
                    metadata={'remaining_codes': remaining_codes})
        
        # Count remaining backup codes
        total_codes = MFABackupCode.objects.filter(user=user).count()
        
        # Warn user if running low on backup codes
        warning = None
        if remaining_codes <= 2:
            warning = f'Warning: Only {remaining_codes} backup codes remaining. Please regenerate codes soon.'
        
        # Create and track session
        session, should_alert, alert_message = SessionManager.create_and_track_session(user, request)
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        response_data = {
            'user': UserSerializer(user).data,
            'message': 'Login successful with backup code',
            'remaining_backup_codes': remaining_codes,
            'backup_codes_status': {
                'total': total_codes,
                'unused': remaining_codes,
                'warning': remaining_codes <= 3 and total_codes > 0
            }
        }
        if warning:
            response_data['warning'] = warning
        
        if should_alert and alert_message:
            response_data['security_alert'] = alert_message
        
        response = Response(response_data)
        set_jwt_cookies(response, str(refresh.access_token), str(refresh))
        
        return response
        
    except User.DoesNotExist:
        AuditLog.log('mfa_backup_used', user=None, request=request, success=False,
                    metadata={'reason': 'user_not_found'})
        return Response({'error': 'Invalid backup code'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_regenerate_backup_codes(request):
    """
    Regenerate backup codes (invalidates all existing codes).
    Requires password confirmation for security.
    """
    password = request.data.get('password')
    
    if not password:
        return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    user = request.user
    
    if not user.mfa_enabled:
        return Response({'error': 'MFA is not enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    if not user.check_password(password):
        AuditLog.log('mfa_backup_generated', user=user, request=request, success=False,
                    metadata={'reason': 'invalid_password'})
        return Response({'error': 'Invalid password'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Generate new backup codes (this deletes old ones)
    backup_codes = MFABackupCode.generate_codes_for_user(user, count=10)
    
    # Log regeneration
    AuditLog.log('mfa_backup_generated', user=user, request=request, success=True)
    
    return Response({
        'message': 'Backup codes regenerated successfully',
        'backup_codes': backup_codes
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mfa_backup_codes_status(request):
    """Get status of backup codes (how many are remaining)"""
    user = request.user
    
    if not user.mfa_enabled:
        return Response({'error': 'MFA is not enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    total_codes = MFABackupCode.objects.filter(user=user).count()
    unused_codes = MFABackupCode.objects.filter(user=user, is_used=False).count()
    used_codes = total_codes - unused_codes
    
    return Response({
        'total': total_codes,
        'unused': unused_codes,
        'used': used_codes,
        'warning': unused_codes <= 2
    })


# ============================================================================
# SESSION MANAGEMENT VIEWS
# ============================================================================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_active_sessions(request):
    """Get all active sessions for the current user"""
    user = request.user
    sessions = SessionManager.get_active_sessions(user)
    
    # Serialize session data
    sessions_data = []
    for session in sessions:
        # Get anomaly reasons if session is anomalous
        anomaly_reasons = []
        if session.is_anomalous and session.anomaly_reasons:
            anomaly_reasons = session.anomaly_reasons if isinstance(session.anomaly_reasons, list) else []
        
        # Calculate expiration (session lasts as long as refresh token - 7 days default)
        expires_at = session.login_at + timedelta(days=7)
        
        sessions_data.append({
            'id': session.id,
            'device_name': session.device_name,
            'device_type': session.device_type,
            'browser': session.browser,
            'os': session.os,
            'ip_address': session.ip_address,
            'location': f"{session.city}, {session.country}" if session.city and session.country else session.country or 'Unknown',
            'location_display': f"{session.city}, {session.country}" if session.city and session.country else session.country or 'Unknown',
            'is_current': session.device_fingerprint == generate_device_fingerprint(request),
            'is_trusted': session.is_trusted,
            'trust_score': session.trust_score,
            'is_anomalous': session.is_anomalous,
            'anomaly_reasons': anomaly_reasons,
            'login_at': session.login_at,
            'created_at': session.login_at,
            'last_activity': session.last_activity,
            'expires_at': expires_at,
        })
    
    # Get session statistics
    stats = SessionManager.get_session_stats(user)
    
    # Check for suspicious patterns
    is_suspicious, patterns = SessionManager.detect_account_takeover_patterns(user)
    
    if is_suspicious:
        stats['security_warning'] = {
            'level': 'high',
            'message': 'Suspicious activity detected on your account',
            'patterns': patterns
        }
    
    return Response({
        'sessions': sessions_data,
        'stats': stats
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_session(request):
    """Revoke a specific session"""
    from .models import UserSession
    from .utils import generate_device_fingerprint
    
    session_id = request.data.get('session_id')
    
    if not session_id:
        return Response({'error': 'Session ID is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        session = UserSession.objects.get(id=session_id, user=request.user)
        
        # Don't allow revoking current session (use logout instead)
        current_fingerprint = generate_device_fingerprint(request)
        if session.device_fingerprint == current_fingerprint:
            return Response(
                {'error': 'Cannot revoke current session. Use logout instead.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        session.revoke(reason='user_requested')
        
        return Response({'message': 'Session revoked successfully'})
        
    except UserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_all_sessions(request):
    """Revoke all sessions except the current one"""
    from .models import UserSession
    from .utils import generate_device_fingerprint
    
    user = request.user
    current_fingerprint = generate_device_fingerprint(request)
    
    # Find current session
    current_session = UserSession.objects.filter(
        user=user,
        device_fingerprint=current_fingerprint,
        is_active=True
    ).first()
    
    # Revoke all except current
    count = SessionManager.revoke_all_user_sessions(
        user,
        except_session_id=current_session.id if current_session else None,
        reason='user_requested_revoke_all'
    )
    
    return Response({
        'message': f'{count} session(s) revoked successfully',
        'revoked_count': count
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def trust_device(request):
    """Mark current device as trusted"""
    from .models import UserSession
    from .utils import generate_device_fingerprint
    
    user = request.user
    device_fingerprint = generate_device_fingerprint(request)
    
    session = UserSession.objects.filter(
        user=user,
        device_fingerprint=device_fingerprint,
        is_active=True
    ).first()
    
    if not session:
        return Response({'error': 'Current session not found'}, status=status.HTTP_404_NOT_FOUND)
    
    session.mark_trusted()
    
    # Log the action
    AuditLog.log(
        'account_locked',  # Reusing this action type for device trust
        user=user,
        request=request,
        success=True,
        metadata={
            'action': 'device_trusted',
            'device': session.device_name,
            'session_id': session.id
        }
    )
    
    return Response({
        'message': 'Device marked as trusted',
        'session': {
            'id': session.id,
            'device_name': session.device_name,
            'is_trusted': session.is_trusted,
            'trust_score': session.trust_score
        }
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def session_stats(request):
    """Get session statistics for the current user"""
    user = request.user
    stats = SessionManager.get_session_stats(user)
    
    # Check for suspicious patterns
    is_suspicious, patterns = SessionManager.detect_account_takeover_patterns(user)
    
    if is_suspicious:
        stats['security_warning'] = {
            'level': 'high',
            'message': 'Suspicious activity detected on your account',
            'patterns': patterns
        }
    
    return Response(stats)


# ============================================================================
# SECURITY MONITORING DASHBOARD
# ============================================================================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_dashboard_combined(request):
    """
    Combined endpoint for security dashboard - returns metrics, events, and statistics in one call
    OPTIMIZED: Uses aggregation queries to reduce database hits
    """
    from django.db.models import Count, Q
    
    user = request.user
    
    # Get query parameters
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 10))
    days = int(request.GET.get('days', 30))
    severity = request.GET.get('severity')
    resolved = request.GET.get('resolved')
    
    # Time ranges
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    start_date = now - timedelta(days=days)
    
    # OPTIMIZATION 1: Single aggregated query for auth metrics (5 queries → 1)
    auth_aggregates = AuditLog.objects.filter(user=user).aggregate(
        total_logins_24h=Count('id', filter=Q(
            action='login_success',
            created_at__gte=last_24h
        )),
        failed_logins_24h=Count('id', filter=Q(
            action='login_failed',
            created_at__gte=last_24h
        )),
        total_logins_7d=Count('id', filter=Q(
            action='login_success',
            created_at__gte=last_7d
        )),
        mfa_verifications_7d=Count('id', filter=Q(
            action='mfa_verify',
            created_at__gte=last_7d
        )),
    )
    
    auth_metrics = {
        **auth_aggregates,
        'mfa_enabled': user.mfa_enabled,
    }
    
    # OPTIMIZATION 2: Single aggregated query for security events (5 queries → 1)
    security_aggregates = SecurityEvent.objects.filter(user=user).aggregate(
        total_events=Count('id'),
        unresolved_events=Count('id', filter=~Q(status='resolved')),
        critical_events=Count('id', filter=Q(
            severity='critical',
        ) & ~Q(status='resolved')),
        high_events=Count('id', filter=Q(
            severity='high',
        ) & ~Q(status='resolved')),
        events_24h=Count('id', filter=Q(created_at__gte=last_24h)),
    )
    
    security_events = security_aggregates
    
    # OPTIMIZATION 3: Single aggregated query for session metrics (4 queries → 1)
    session_aggregates = UserSession.objects.filter(user=user).aggregate(
        active_sessions=Count('id', filter=Q(is_active=True)),
        trusted_devices=Count('id', filter=Q(
            is_trusted=True,
            is_active=True
        )),
        anomalous_sessions=Count('id', filter=Q(
            is_anomalous=True,
            is_active=True
        )),
        unique_locations_7d=Count('country', distinct=True, filter=Q(
            login_at__gte=last_7d
        )),
    )
    
    session_metrics = session_aggregates
    
    # 4. Recent activity
    recent_activities = AuditLog.objects.filter(
        user=user
    ).order_by('-created_at')[:10]
    
    activities = [{
        'id': log.id,
        'action': log.action,
        'success': log.success,
        'timestamp': log.created_at,
        'ip_address': log.ip_address,
    } for log in recent_activities]
    
    # 5. Security events list (paginated)
    queryset = SecurityEvent.objects.filter(user=user).order_by('-created_at')
    
    if severity:
        queryset = queryset.filter(severity=severity)
    
    if resolved is not None:
        is_resolved = resolved.lower() == 'true'
        if is_resolved:
            queryset = queryset.filter(status='resolved')
        else:
            queryset = queryset.exclude(status='resolved')
    
    total = queryset.count()
    start = (page - 1) * page_size
    end = start + page_size
    events = queryset[start:end]
    
    events_data = [{
        'id': event.id,
        'event_type': event.event_type,
        'severity': event.severity,
        'description': event.description,
        'ip_address': event.ip_address,
        'resolved': event.status == 'resolved',
        'resolved_at': event.resolved_at,
        'resolved_by': event.resolved_by.username if event.resolved_by else None,
        'resolution_notes': event.resolution_notes,
        'created_at': event.created_at,
    } for event in events]
    
    # 6. Statistics
    top_ips = AuditLog.objects.filter(
        user=user,
        created_at__gte=start_date
    ).values('ip_address').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    device_distribution = UserSession.objects.filter(
        user=user,
        login_at__gte=start_date
    ).values('device_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    return Response({
        'auth_metrics': auth_metrics,
        'security_events': security_events,
        'session_metrics': session_metrics,
        'recent_activities': activities,
        'events': {
            'data': events_data,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
        },
        'statistics': {
            'top_ips': list(top_ips),
            'device_distribution': list(device_distribution),
        }
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_dashboard_metrics(request):
    """
    Get comprehensive security metrics for dashboard
    DEPRECATED: Use security_dashboard_combined instead
    """
    user = request.user
    
    # Time ranges
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)
    
    # Authentication metrics
    auth_metrics = {
        'total_logins_24h': AuditLog.objects.filter(
            user=user,
            action='login_success',
            created_at__gte=last_24h
        ).count(),
        'failed_logins_24h': AuditLog.objects.filter(
            user=user,
            action='login_failed',
            created_at__gte=last_24h
        ).count(),
        'total_logins_7d': AuditLog.objects.filter(
            user=user,
            action='login_success',
            created_at__gte=last_7d
        ).count(),
        'mfa_enabled': user.mfa_enabled,
        'mfa_verifications_7d': AuditLog.objects.filter(
            user=user,
            action='mfa_verify',
            created_at__gte=last_7d
        ).count(),
    }
    
    # Security events
    security_events = {
        'total_events': SecurityEvent.objects.filter(user=user).count(),
        'unresolved_events': SecurityEvent.objects.filter(
            user=user,
        ).exclude(status='resolved').count(),
        'critical_events': SecurityEvent.objects.filter(
            user=user,
            severity='critical',
        ).exclude(status='resolved').count(),
        'high_events': SecurityEvent.objects.filter(
            user=user,
            severity='high',
        ).exclude(status='resolved').count(),
        'events_24h': SecurityEvent.objects.filter(
            user=user,
            created_at__gte=last_24h
        ).count(),
    }
    
    # Session metrics
    session_metrics = {
        'active_sessions': UserSession.objects.filter(
            user=user,
            is_active=True
        ).count(),
        'trusted_devices': UserSession.objects.filter(
            user=user,
            is_trusted=True,
            is_active=True
        ).count(),
        'anomalous_sessions': UserSession.objects.filter(
            user=user,
            is_anomalous=True,
            is_active=True
        ).count(),
        'unique_locations_7d': UserSession.objects.filter(
            user=user,
            login_at__gte=last_7d
        ).values('country').distinct().count(),
    }
    
    # Risk assessment
    recent_failed_logins = AuditLog.objects.filter(
        user=user,
        action='login_failed',
        created_at__gte=last_24h
    ).count()
    
    unresolved_critical = SecurityEvent.objects.filter(
        user=user,
        severity='critical',
    ).exclude(status='resolved').count()
    
    # Calculate overall risk score
    risk_score = 0
    risk_level = 'low'
    risk_factors = []
    
    if recent_failed_logins > 5:
        risk_score += 30
        risk_factors.append(f'{recent_failed_logins} failed login attempts in 24h')
    
    if unresolved_critical > 0:
        risk_score += 40
        risk_factors.append(f'{unresolved_critical} unresolved critical events')
    
    if not user.mfa_enabled:
        risk_score += 20
        risk_factors.append('MFA not enabled')
    
    if session_metrics['anomalous_sessions'] > 0:
        risk_score += 25
        risk_factors.append(f'{session_metrics["anomalous_sessions"]} anomalous sessions')
    
    if risk_score >= 70:
        risk_level = 'critical'
    elif risk_score >= 50:
        risk_level = 'high'
    elif risk_score >= 30:
        risk_level = 'medium'
    
    risk_assessment = {
        'risk_score': min(risk_score, 100),
        'risk_level': risk_level,
        'risk_factors': risk_factors,
    }
    
    # Recent activity
    recent_activities = AuditLog.objects.filter(
        user=user
    ).order_by('-created_at')[:10]
    
    activities = [{
        'id': log.id,
        'action': log.action,
        'success': log.success,
        'timestamp': log.created_at,
        'ip_address': log.ip_address,
    } for log in recent_activities]
    
    return Response({
        'auth_metrics': auth_metrics,
        'security_events': security_events,
        'session_metrics': session_metrics,
        'risk_assessment': risk_assessment,
        'recent_activities': activities,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_events_list(request):
    """
    Get paginated list of security events
    """
    user = request.user
    
    # Query parameters
    severity = request.GET.get('severity')
    resolved = request.GET.get('resolved')
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 20))
    
    # Base queryset
    queryset = SecurityEvent.objects.filter(user=user).order_by('-created_at')
    
    # Filters
    if severity:
        queryset = queryset.filter(severity=severity)
    
    if resolved is not None:
        is_resolved = resolved.lower() == 'true'
        if is_resolved:
            queryset = queryset.filter(status='resolved')
        else:
            queryset = queryset.exclude(status='resolved')
    
    # Pagination
    total = queryset.count()
    start = (page - 1) * page_size
    end = start + page_size
    events = queryset[start:end]
    
    events_data = [{
        'id': event.id,
        'event_type': event.event_type,
        'severity': event.severity,
        'description': event.description,
        'ip_address': event.ip_address,
        'resolved': event.status == 'resolved',
        'resolved_at': event.resolved_at,
        'resolved_by': event.resolved_by.username if event.resolved_by else None,
        'resolution_notes': event.resolution_notes,
        'created_at': event.created_at,
    } for event in events]
    
    return Response({
        'events': events_data,
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': (total + page_size - 1) // page_size,
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def security_event_resolve(request, event_id):
    """
    Resolve a security event
    """
    user = request.user
    resolution_notes = request.data.get('resolution_notes', '')
    
    try:
        event = SecurityEvent.objects.get(id=event_id, user=user)
        
        if event.status == 'resolved':
            return Response(
                {'error': 'Event is already resolved'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        event.mark_resolved(user, resolution_notes)
        
        # Log the resolution
        AuditLog.log(
            action='security_event_resolved',
            user=user,
            request=request,
            success=True,
            metadata={
                'event_id': event_id,
                'event_type': event.event_type,
                'severity': event.severity,
            }
        )
        
        return Response({
            'message': 'Security event resolved successfully',
            'event': {
                'id': event.id,
                'resolved': event.resolved,
                'resolved_at': event.resolved_at,
                'resolved_by': user.username,
            }
        })
        
    except SecurityEvent.DoesNotExist:
        return Response(
            {'error': 'Security event not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_audit_logs(request):
    """
    Get paginated audit logs
    """
    user = request.user
    
    # Query parameters
    action = request.GET.get('action')
    success = request.GET.get('success')
    risk_level = request.GET.get('risk_level')
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 50))
    
    # Base queryset
    queryset = AuditLog.objects.filter(user=user).order_by('-created_at')
    
    # Filters
    if action:
        queryset = queryset.filter(action=action)
    
    if success is not None:
        is_success = success.lower() == 'true'
        queryset = queryset.filter(success=is_success)
    
    if risk_level:
        queryset = queryset.filter(risk_level=risk_level)
    
    # Pagination
    total = queryset.count()
    start = (page - 1) * page_size
    end = start + page_size
    logs = queryset[start:end]
    
    logs_data = [{
        'id': log.id,
        'action': log.action,
        'success': log.success,
        'timestamp': log.created_at,
        'ip_address': log.ip_address,
        'user_agent': log.user_agent,
        'metadata': log.metadata,
    } for log in logs]
    
    return Response({
        'logs': logs_data,
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': (total + page_size - 1) // page_size,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_statistics(request):
    """
    Get detailed security statistics and trends
    """
    user = request.user
    
    # Time ranges
    now = timezone.now()
    days_back = int(request.GET.get('days', 30))
    start_date = now - timedelta(days=days_back)
    
    # Daily login trends
    daily_logins = []
    for i in range(days_back):
        day = start_date + timedelta(days=i)
        next_day = day + timedelta(days=1)
        
        successful = AuditLog.objects.filter(
            user=user,
            action='login_success',
            created_at__gte=day,
            created_at__lt=next_day
        ).count()
        
        failed = AuditLog.objects.filter(
            user=user,
            action='login_failed',
            created_at__gte=day,
            created_at__lt=next_day
        ).count()
        
        daily_logins.append({
            'date': day.strftime('%Y-%m-%d'),
            'successful': successful,
            'failed': failed,
        })
    
    # Security events by severity
    events_by_severity = {}
    for severity_choice in ['low', 'medium', 'high', 'critical']:
        events_by_severity[severity_choice] = SecurityEvent.objects.filter(
            user=user,
            severity=severity_choice,
            created_at__gte=start_date
        ).count()
    
    # Top IP addresses
    top_ips = AuditLog.objects.filter(
        user=user,
        created_at__gte=start_date
    ).values('ip_address').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Device types distribution
    device_distribution = UserSession.objects.filter(
        user=user,
        login_at__gte=start_date
    ).values('device_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Geographic distribution
    geo_distribution = UserSession.objects.filter(
        user=user,
        login_at__gte=start_date
    ).exclude(country__isnull=True).values('country', 'city').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Action distribution
    action_distribution = AuditLog.objects.filter(
        user=user,
        created_at__gte=start_date
    ).values('action').annotate(
        count=Count('id')
    ).order_by('-count')[:15]
    
    return Response({
        'period_days': days_back,
        'start_date': start_date,
        'end_date': now,
        'daily_logins': daily_logins,
        'events_by_severity': events_by_severity,
        'top_ips': list(top_ips),
        'device_distribution': list(device_distribution),
        'geo_distribution': list(geo_distribution),
        'action_distribution': list(action_distribution),
    })
