import { useEffect, useRef } from 'react';

/**
 * Cloudflare Turnstile CAPTCHA Component
 * 
 * This component renders the Cloudflare Turnstile widget, a privacy-first
 * CAPTCHA alternative that provides better UX than reCAPTCHA.
 * 
 * Features:
 * - Free unlimited requests
 * - Privacy-focused (no tracking)
 * - Invisible challenges when possible
 * - Better accessibility
 * 
 * Usage:
 * ```jsx
 * <Turnstile
 *   siteKey="your-site-key"
 *   onSuccess={(token) => console.log('Token:', token)}
 *   onError={(error) => console.error('Error:', error)}
 * />
 * ```
 */

const Turnstile = ({ 
  siteKey, 
  onSuccess, 
  onError, 
  onExpire,
  theme = 'auto',
  size = 'normal',
  action,
  cData,
  appearance = 'always',
  refreshExpired = 'auto'
}) => {
  const containerRef = useRef(null);
  const widgetIdRef = useRef(null);

  useEffect(() => {
    // Load Turnstile script if not already loaded
    if (!window.turnstile) {
      const script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
      script.async = true;
      script.defer = true;
      script.onload = () => initializeTurnstile();
      script.onerror = () => {
        console.error('Failed to load Cloudflare Turnstile script');
        if (onError) {
          onError('Failed to load CAPTCHA script');
        }
      };
      document.head.appendChild(script);
    } else {
      initializeTurnstile();
    }

    return () => {
      // Cleanup: remove widget when component unmounts
      if (window.turnstile && widgetIdRef.current !== null) {
        try {
          window.turnstile.remove(widgetIdRef.current);
        } catch (error) {
          console.warn('Failed to remove Turnstile widget:', error);
        }
      }
    };
  }, [siteKey]);

  const initializeTurnstile = () => {
    if (!window.turnstile || !containerRef.current) return;

    // Remove existing widget if present
    if (widgetIdRef.current !== null) {
      try {
        window.turnstile.remove(widgetIdRef.current);
      } catch (error) {
        console.warn('Failed to remove existing Turnstile widget:', error);
      }
    }

    // Clear container
    if (containerRef.current) {
      containerRef.current.innerHTML = '';
    }

    // Render new widget
    try {
      widgetIdRef.current = window.turnstile.render(containerRef.current, {
        sitekey: siteKey,
        theme: theme,
        size: size,
        action: action,
        cData: cData,
        appearance: appearance,
        'refresh-expired': refreshExpired,
        callback: (token) => {
          if (onSuccess) {
            onSuccess(token);
          }
        },
        'error-callback': (error) => {
          console.error('Turnstile error:', error);
          if (onError) {
            onError(error);
          }
        },
        'expired-callback': () => {
          if (onExpire) {
            onExpire();
          }
        },
      });
    } catch (error) {
      console.error('Failed to render Turnstile widget:', error);
      if (onError) {
        onError('Failed to initialize CAPTCHA');
      }
    }
  };

  /**
   * Reset the widget (call externally if needed)
   */
  const reset = () => {
    if (window.turnstile && widgetIdRef.current !== null) {
      try {
        window.turnstile.reset(widgetIdRef.current);
      } catch (error) {
        console.error('Failed to reset Turnstile widget:', error);
      }
    }
  };

  /**
   * Get current token (call externally if needed)
   */
  const getResponse = () => {
    if (window.turnstile && widgetIdRef.current !== null) {
      try {
        return window.turnstile.getResponse(widgetIdRef.current);
      } catch (error) {
        console.error('Failed to get Turnstile response:', error);
        return null;
      }
    }
    return null;
  };

  // Expose methods via ref (optional)
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.reset = reset;
      containerRef.current.getResponse = getResponse;
    }
  }, []);

  return (
    <div 
      ref={containerRef} 
      className="turnstile-widget"
      style={{ minHeight: size === 'compact' ? '65px' : '65px' }}
    />
  );
};

export default Turnstile;
