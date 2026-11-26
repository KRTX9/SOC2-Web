from django.urls import path
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from . import views
from .authentication import google_login_view, LoginRateThrottle

# Wrap google_login_view with decorators + rate limiting
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def google_login(request):
    return google_login_view(request)

urlpatterns = [
    # Authentication
    path('csrf/', views.get_csrf_token, name='get_csrf_token'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('google/login/', google_login, name='google_login'),
    path('logout/', views.logout, name='logout'),
    path('me/', views.current_user, name='current_user'),
    path('token/refresh/', views.refresh_token, name='token_refresh'),  
    
    # Email Verification
    path('verify-email-otp/', views.verify_email_otp, name='verify_email_otp'),
    path('resend-verification/', views.resend_verification, name='resend_verification'),
    
    # Password Management
    path('password/reset/request/', views.password_reset_request, name='password_reset_request'),
    path('password/reset/verify/', views.password_reset_verify, name='password_reset_verify'),
    path('password/change/', views.password_change, name='password_change'),

    # MFA (Multi-Factor Authentication)
    path('mfa/setup/', views.mfa_setup, name='mfa_setup'),
    path('mfa/enable/', views.mfa_enable, name='mfa_enable'),
    path('mfa/disable/', views.mfa_disable, name='mfa_disable'),
    path('mfa/verify/', views.mfa_verify_login, name='mfa_verify_login'),
    path('mfa/verify-backup/', views.mfa_verify_backup_code, name='mfa_verify_backup_code'),
    path('mfa/backup-codes/regenerate/', views.mfa_regenerate_backup_codes, name='mfa_regenerate_backup_codes'),
    path('mfa/backup-codes/status/', views.mfa_backup_codes_status, name='mfa_backup_codes_status'),
    
    # Session Management
    path('sessions/', views.get_active_sessions, name='get_active_sessions'),
    path('sessions/<int:session_id>/revoke/', views.revoke_session, name='revoke_session'),
    path('sessions/revoke-all/', views.revoke_all_sessions, name='revoke_all_sessions'),
    path('sessions/<int:session_id>/trust/', views.trust_device, name='trust_device'),
    path('sessions/stats/', views.session_stats, name='session_stats'),
    
    # Security Monitoring Dashboard
    path('security/dashboard/', views.security_dashboard_combined, name='security_dashboard_combined'),
    path('security/dashboard/metrics/', views.security_dashboard_metrics, name='security_dashboard_metrics'),
    path('security/events/', views.security_events_list, name='security_events_list'),
    path('security/events/<int:event_id>/resolve/', views.security_event_resolve, name='security_event_resolve'),
    path('security/audit-logs/', views.security_audit_logs, name='security_audit_logs'),
    path('security/statistics/', views.security_statistics, name='security_statistics'),
]

