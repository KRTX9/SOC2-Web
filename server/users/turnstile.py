"""
Cloudflare Turnstile CAPTCHA Integration

Cloudflare Turnstile is a privacy-first CAPTCHA alternative that is:
- Free for unlimited requests
- No data collection
- Better user experience than reCAPTCHA
- Invisible challenges when possible

Setup Instructions:
1. Go to https://dash.cloudflare.com/
2. Navigate to Turnstile
3. Create a new site
4. Add your domain (use localhost for development)
5. Copy Site Key and Secret Key to .env file
"""

import requests
from django.conf import settings
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class TurnstileVerificationError(Exception):
    """Raised when Turnstile verification fails"""
    pass


def verify_turnstile_token(token: str, ip_address: Optional[str] = None) -> Tuple[bool, str]:
    """
    Verify Cloudflare Turnstile token
    
    Args:
        token: The Turnstile response token from the client
        ip_address: Optional IP address of the user for additional verification
    
    Returns:
        Tuple of (success: bool, error_message: str)
    
    Error Codes:
        - missing-input-secret: Secret key is missing
        - invalid-input-secret: Secret key is invalid
        - missing-input-response: Token is missing
        - invalid-input-response: Token is invalid or expired
        - timeout-or-duplicate: Token has timed out or already been used
        - internal-error: Cloudflare internal error
    """
    
    # Get Turnstile secret from settings
    secret_key = getattr(settings, 'TURNSTILE_SECRET_KEY', None)
    
    if not secret_key:
        logger.warning("TURNSTILE_SECRET_KEY not configured in settings")
        return False, "CAPTCHA verification is not configured"
    
    # Only bypass with test keys (starting with 1x or 2x for dummy/visible always)
    # Test keys: https://developers.cloudflare.com/turnstile/reference/testing/
    if secret_key.startswith('1x') or secret_key.startswith('2x') or secret_key.startswith('3x'):
        logger.info("Using Turnstile test key - bypassing verification")
        return True, ""
    
    if not token:
        return False, "CAPTCHA token is required"
    
    # Cloudflare Turnstile verification endpoint
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    
    # Prepare verification payload
    payload = {
        'secret': secret_key,
        'response': token,
    }
    
    # Include IP address if provided for additional verification
    if ip_address:
        payload['remoteip'] = ip_address
    
    try:
        # Send verification request to Cloudflare
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        
        result = response.json()
        
        # Check if verification was successful
        if result.get('success'):
            logger.info(f"Turnstile verification successful. Challenge timestamp: {result.get('challenge_ts')}")
            return True, ""
        
        # Verification failed - extract error codes
        error_codes = result.get('error-codes', [])
        
        # Map error codes to user-friendly messages
        error_messages = {
            'missing-input-secret': 'CAPTCHA configuration error',
            'invalid-input-secret': 'CAPTCHA configuration error',
            'missing-input-response': 'CAPTCHA token is required',
            'invalid-input-response': 'CAPTCHA verification failed. Please try again',
            'timeout-or-duplicate': 'CAPTCHA has expired. Please refresh and try again',
            'internal-error': 'CAPTCHA service error. Please try again',
        }
        
        # Get the first error message
        if error_codes:
            first_error = error_codes[0]
            error_message = error_messages.get(first_error, 'CAPTCHA verification failed')
            logger.warning(f"Turnstile verification failed: {first_error}")
        else:
            error_message = 'CAPTCHA verification failed'
            logger.warning("Turnstile verification failed with no error codes")
        
        return False, error_message
        
    except requests.exceptions.Timeout:
        logger.error("Turnstile verification timeout")
        return False, "CAPTCHA verification timeout. Please try again"
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Turnstile verification request error: {str(e)}")
        return False, "CAPTCHA verification error. Please try again"
    
    except Exception as e:
        logger.error(f"Unexpected error during Turnstile verification: {str(e)}")
        return False, "An unexpected error occurred. Please try again"


def verify_turnstile_or_bypass(token: str, ip_address: Optional[str] = None) -> Tuple[bool, str]:
    """
    Verify Turnstile token with automatic bypass for test keys only
    
    This wrapper only bypasses verification when using Cloudflare's official
    test keys (starting with 1x, 2x, or 3x).
    
    Args:
        token: The Turnstile response token from the client
        ip_address: Optional IP address of the user
    
    Returns:
        Tuple of (success: bool, error_message: str)
    """
    return verify_turnstile_token(token, ip_address)


def calculate_bot_score(request) -> int:
    """
    Calculate a bot likelihood score (0-100)
    
    This is a simple heuristic-based scoring system that can be used
    alongside Turnstile for additional bot detection.
    
    Factors:
    - User agent presence and validity
    - Request headers
    - Referer presence
    - Accept headers
    
    Returns:
        Bot score from 0 (definitely human) to 100 (definitely bot)
    """
    
    score = 0
    
    # Check User-Agent
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    if not user_agent:
        score += 40  # No user agent is very suspicious
    elif len(user_agent) < 20:
        score += 30  # Very short user agent
    elif 'bot' in user_agent.lower() or 'crawler' in user_agent.lower():
        score += 50  # Self-identified bot
    
    # Check for common headers
    if not request.META.get('HTTP_ACCEPT'):
        score += 20  # Missing Accept header
    
    if not request.META.get('HTTP_ACCEPT_LANGUAGE'):
        score += 15  # Missing Accept-Language header
    
    # Check Referer (should be present for form submissions)
    referer = request.META.get('HTTP_REFERER', '')
    if not referer and request.method == 'POST':
        score += 10  # POST without referer is suspicious
    
    # Check for common bot indicators in headers
    suspicious_headers = ['X-Forwarded-For', 'X-ProxyUser-Ip']
    for header in suspicious_headers:
        if request.META.get(f'HTTP_{header.upper().replace("-", "_")}'):
            score += 5
    
    return min(score, 100)


def should_require_captcha(request, action: str) -> bool:
    """
    Determine if CAPTCHA should be required for this request
    
    This can be used to implement adaptive CAPTCHA requirements based on
    risk factors, rate limiting, or user behavior.
    
    Args:
        request: Django request object
        action: Action being performed (login, register, etc.)
    
    Returns:
        True if CAPTCHA should be required, False otherwise
    """
    
    # Always require CAPTCHA in production
    if not settings.DEBUG:
        return True
    
    # Calculate bot score
    bot_score = calculate_bot_score(request)
    
    # Require CAPTCHA if bot score is high
    if bot_score > 50:
        logger.info(f"Requiring CAPTCHA due to high bot score: {bot_score}")
        return True
    
    # Check rate limiting - if user has made many requests, require CAPTCHA
    # This would integrate with your rate limiting system
    
    # For now, in DEBUG mode, make CAPTCHA optional
    return False
