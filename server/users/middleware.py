"""
Custom middleware for audit logging and security monitoring.
"""
from django.utils.deprecation import MiddlewareMixin
from .models import AuditLog
from .utils import get_client_ip
import logging

logger = logging.getLogger(__name__)


class AuditLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to automatically log authentication-related requests.
    Captures all requests to /api/auth/* endpoints.
    """
    
    # Endpoints to automatically log
    LOGGED_ENDPOINTS = [
        '/api/auth/login/',
        '/api/auth/logout/',
        '/api/auth/register/',
        '/api/auth/google/login/',
        '/api/auth/token/refresh/',
        '/api/auth/password/change/',
        '/api/auth/password/reset/request/',
        '/api/auth/password/reset/verify/',
        '/api/auth/mfa/setup/',
        '/api/auth/mfa/enable/',
        '/api/auth/mfa/disable/',
        '/api/auth/mfa/verify/',
    ]
    
    def process_response(self, request, response):
        """
        Log authentication requests after response is generated.
        This allows us to know if the request was successful.
        """
        # Only log configured endpoints
        if not any(request.path.startswith(endpoint) for endpoint in self.LOGGED_ENDPOINTS):
            return response
        
        # Skip if already logged (views handle their own logging)
        if hasattr(request, '_audit_logged'):
            return response
        
        # Determine action type from path
        action = self._determine_action(request.path)
        if not action:
            return response
        
        # Determine success based on status code
        success = 200 <= response.status_code < 400
        
        # Get user (if authenticated)
        user = request.user if request.user.is_authenticated else None
        
        # Extract metadata
        metadata = {
            'status_code': response.status_code,
            'method': request.method,
        }
        
        # Log the event
        try:
            AuditLog.log(
                action=action,
                user=user,
                request=request,
                success=success,
                metadata=metadata
            )
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
        
        return response
    
    def _determine_action(self, path):
        """Map request path to action type"""
        path_action_map = {
            '/api/auth/login/': 'login_success',  # Will be overridden by view if failed
            '/api/auth/logout/': 'logout',
            '/api/auth/register/': 'register',
            '/api/auth/google/login/': 'google_login_success',
            '/api/auth/token/refresh/': 'token_refresh',
            '/api/auth/password/change/': 'password_change',
            '/api/auth/password/reset/request/': 'password_reset_request',
            '/api/auth/password/reset/verify/': 'password_reset_success',
            '/api/auth/mfa/setup/': 'mfa_enabled',
            '/api/auth/mfa/enable/': 'mfa_enabled',
            '/api/auth/mfa/disable/': 'mfa_disabled',
            '/api/auth/mfa/verify/': 'mfa_verify_success',
        }
        
        for endpoint, action in path_action_map.items():
            if path.startswith(endpoint):
                return action
        
        return None


class SecurityMonitoringMiddleware(MiddlewareMixin):
    """
    Middleware for real-time security threat detection.
    Monitors for suspicious patterns and potential attacks.
    """
    
    # Suspicious patterns in request paths and parameters
    SUSPICIOUS_PATTERNS = [
        # SQL Injection attempts
        r'(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table)',
        # XSS attempts (but not in legitimate HTML attributes)
        r'(?i)(<script[^>]*>|javascript:\s*[^;]|onerror\s*=|onload\s*=)',
        # Path traversal
        r'(\.\./|\.\.\\)',
        # Command injection (exclude URL query parameters)
        # Match shell commands but not URL ampersands
        r'(?i)(;\s*(?:ls|rm|cat|wget|curl)|^\||&\s*(?:ls|rm|cat|wget|curl)|\$\()',
    ]
    
    def process_request(self, request):
        """Check for suspicious activity before processing request"""
        import re
        from .models import SecurityEvent
        
        # Check for suspicious patterns in path and query string
        full_path = request.get_full_path()
        
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, full_path):
                # Log security event
                try:
                    SecurityEvent.create_event(
                        event_type='sql_injection' if 'union' in pattern.lower() else 'xss_attempt',
                        severity='high',
                        ip_address=get_client_ip(request),
                        description=f'Suspicious pattern detected in request: {pattern}',
                        user=request.user if request.user.is_authenticated else None,
                        details={
                            'path': request.path,
                            'full_path': full_path,
                            'method': request.method,
                            'pattern': pattern,
                        },
                        risk_score=85
                    )
                except Exception as e:
                    logger.error(f"Failed to create security event: {e}")
                
                # Don't block the request (might be false positive)
                # Just log and continue
                break
        
        return None
