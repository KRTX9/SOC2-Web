"""
Utility functions for user authentication and security.
"""
import re
from user_agents import parse


def get_client_ip(request):
    """
    Extract client IP address from request, handling proxies and load balancers.
    Checks X-Forwarded-For, X-Real-IP headers before falling back to REMOTE_ADDR.
    """
    # Check common proxy headers (in order of preference)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2, ...)
        # The first one is usually the original client IP
        ip = x_forwarded_for.split(',')[0].strip()
        if is_valid_ip(ip):
            return ip
    
    x_real_ip = request.META.get('HTTP_X_REAL_IP')
    if x_real_ip and is_valid_ip(x_real_ip):
        return x_real_ip
    
    # Fallback to REMOTE_ADDR (direct connection IP)
    remote_addr = request.META.get('REMOTE_ADDR', '0.0.0.0')
    return remote_addr if is_valid_ip(remote_addr) else '0.0.0.0'


def is_valid_ip(ip):
    """Check if string is a valid IPv4 or IPv6 address"""
    ipv4_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    ipv6_pattern = re.compile(
        r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,7}:|'
        r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
        r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
        r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
        r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
        r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
        r'::(ffff(:0{1,4}){0,1}:){0,1}'
        r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
        r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
        r'([0-9a-fA-F]{1,4}:){1,4}:'
        r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
        r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
    )
    
    return bool(ipv4_pattern.match(ip) or ipv6_pattern.match(ip))


def parse_user_agent(user_agent_string):
    """
    Parse user agent string to extract device information.
    Returns dict with device_type, browser, os, etc.
    """
    if not user_agent_string:
        return {
            'device_type': 'unknown',
            'browser': 'unknown',
            'browser_version': 'unknown',
            'os': 'unknown',
            'os_version': 'unknown',
        }
    
    user_agent = parse(user_agent_string)
    
    # Determine device type
    if user_agent.is_mobile:
        device_type = 'mobile'
    elif user_agent.is_tablet:
        device_type = 'tablet'
    elif user_agent.is_pc:
        device_type = 'desktop'
    elif user_agent.is_bot:
        device_type = 'bot'
    else:
        device_type = 'unknown'
    
    return {
        'device_type': device_type,
        'browser': user_agent.browser.family,
        'browser_version': user_agent.browser.version_string,
        'os': user_agent.os.family,
        'os_version': user_agent.os.version_string,
        'device_brand': user_agent.device.brand or 'unknown',
        'device_model': user_agent.device.model or 'unknown',
        'is_bot': user_agent.is_bot,
    }


def generate_device_fingerprint(request):
    """
    Generate a device fingerprint based on user agent and other request metadata.
    Not cryptographically secure, but useful for tracking devices.
    """
    import hashlib
    
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    accept_language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
    accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', '')
    
    # Combine headers for fingerprint
    fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}"
    
    # Hash for consistent length
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]


def timing_safe_compare(a, b):
    """
    Timing-safe string comparison to prevent timing attacks.
    Useful for comparing security tokens, emails, etc.
    """
    import hmac
    
    if not isinstance(a, str):
        a = str(a)
    if not isinstance(b, str):
        b = str(b)
    
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


def constant_time_response_delay():
    """
    Add a small constant delay to responses to prevent timing attacks.
    Use this for authentication endpoints to prevent user enumeration via timing.
    """
    import time
    import random
    
    # Random delay between 50-150ms to prevent timing analysis
    delay = random.uniform(0.05, 0.15)
    time.sleep(delay)
