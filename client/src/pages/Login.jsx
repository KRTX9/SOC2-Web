import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { GoogleLogin } from "@react-oauth/google";
import { useAuthStore } from "../stores/authStore";
import { authAPI, getErrorMessage } from "../services/api";
import { useGoogleOneTap } from "../hooks/useGoogleOneTap";
import LoadingSpinner from "../Components/LoadingSpinner";
import Turnstile from "../Components/Turnstile";
import toast from "react-hot-toast";
import { MessageSquare, Eye, EyeOff, KeyRound } from "lucide-react";

const TURNSTILE_SITE_KEY = import.meta.env.VITE_TURNSTILE_SITE_KEY || '';

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [backupCode, setBackupCode] = useState("");
  const [turnstileToken, setTurnstileToken] = useState("");
  const [turnstileKey, setTurnstileKey] = useState(0); // Force re-render of Turnstile
  const { login, setUser, setIsAuthenticated } = useAuthStore();
  const navigate = useNavigate();

  // Google One Tap auto-popup
  useGoogleOneTap({
    disabled: false,
    context: "signin",
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (isLoading) return;

    // Check if Turnstile token is present (in production)
    if (!turnstileToken && TURNSTILE_SITE_KEY) {
      setError("Please complete the CAPTCHA verification");
      toast.error("Please complete the CAPTCHA verification");
      return;
    }

    setIsLoading(true);
    setError("");

    const result = await login({ email, password, turnstile_token: turnstileToken });
    setIsLoading(false);

    if (!result) {
      const msg = "No response from server";
      setError(msg);
      toast.error(msg);
      // Reset Turnstile on error
      setTurnstileToken("");
      setTurnstileKey(prev => prev + 1);
      return;
    }

    // MFA required - show MFA input
    if (result.mfa_required) {
      setMfaToken(result.mfa_token);
      setMfaRequired(true);
      // Don't reset Turnstile here - MFA is part of successful auth flow
      return;
    }

    // Login successful
    if (result.success) {
      // Show security alert if present
      if (result.security_alert) {
        toast.warning(result.security_alert, { duration: 6000 });
      }
      
      toast.success("Welcome back!");
      setTimeout(() => navigate("/dashboard"), 100);
      return;
    }

    // Login failed
    if (result.error) {
      setError(result.error);
      toast.error(result.error);
      // Reset Turnstile widget on error to get a new token
      setTurnstileToken("");
      setTurnstileKey(prev => prev + 1);
    }
  };

  const handleMfaSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      const response = await authAPI.mfaVerifyLogin({
        mfa_token: mfaToken,
        mfa_code: mfaCode,
      });

      const { user, security_alert, backup_codes_status } = response.data;
      setUser(user);
      setIsAuthenticated(true);

      toast.success("Login successful!");
      
      // Show security alert if present
      if (security_alert) {
        setTimeout(() => toast.warning(security_alert, { duration: 6000 }), 1000);
      }
      
      // Show backup codes warning if needed
      if (backup_codes_status && backup_codes_status.warning) {
        setTimeout(() => 
          toast.warning(`Only ${backup_codes_status.unused} backup codes remaining`), 
          1500
        );
      }
      
      navigate("/dashboard");
    } catch (err) {
      const errorMsg = getErrorMessage(err);
      setError(errorMsg);
      toast.error(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleBackupCodeSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      const response = await authAPI.mfaVerifyBackupCode({
        mfa_token: mfaToken,
        backup_code: backupCode,
      });

      const { user, warning, remaining_backup_codes, security_alert, backup_codes_status } = response.data;
      setUser(user);
      setIsAuthenticated(true);

      toast.success("Login successful with backup code!");
      
      if (security_alert) {
        setTimeout(() => toast.warning(security_alert, { duration: 6000 }), 1000);
      } else if (warning) {
        setTimeout(() => toast.warning(warning), 1000);
      } else if (backup_codes_status && backup_codes_status.warning) {
        setTimeout(() => 
          toast.warning(`Only ${backup_codes_status.unused} backup codes remaining`), 
          1000
        );
      } else if (remaining_backup_codes !== undefined && remaining_backup_codes <= 3) {
        setTimeout(() => 
          toast.warning(`Only ${remaining_backup_codes} backup codes remaining`), 
          1000
        );
      }

      navigate("/dashboard");
    } catch (err) {
      const errorMsg = getErrorMessage(err);
      setError(errorMsg);
      toast.error(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleSuccess = async (credentialResponse) => {
    setIsLoading(true);
    setError("");

    try {
      const response = await authAPI.googleLogin(credentialResponse.credential);

      setUser(response.data.user);
      setIsAuthenticated(true);
      toast.success("Google login successful!");
      navigate("/dashboard");
    } catch (error) {
      const errorMsg = getErrorMessage(error);
      setError(errorMsg);
      toast.error(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleError = () => {
    toast.error("Google login failed");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-dark-bg via-dark-surface to-dark-bg px-4 relative overflow-hidden">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-brand-primary opacity-10 rounded-full blur-3xl animate-pulse-slow"></div>
        <div
          className="absolute -bottom-40 -left-40 w-80 h-80 bg-brand-secondary opacity-10 rounded-full blur-3xl animate-pulse-slow"
          style={{ animationDelay: "1s" }}
        ></div>
      </div>

      <div className="max-w-md w-full relative z-10">
        <div className="bg-dark-card rounded-2xl shadow-dark-xl p-8 border border-dark-border backdrop-blur-sm">
          <div className="text-center mb-8">
            <div className="flex justify-center mb-4">
              <div className="relative">
                <MessageSquare className="w-16 h-16 text-brand-primary animate-pulse" />
                <div className="absolute inset-0 bg-brand-primary opacity-20 blur-xl rounded-full"></div>
              </div>
            </div>
            <h1 className="text-4xl font-bold gradient-text mb-2">
              SecureAuth
            </h1>
            <p className="text-dark-text-secondary">
              {mfaRequired ? "Enter MFA Code" : "Sign in to your account"}
            </p>
          </div>

          {/* MFA Code or Backup Code Form */}
          {mfaRequired ? (
            useBackupCode ? (
              // Backup Code Form
              <form onSubmit={handleBackupCodeSubmit} className="space-y-6">
                {error && (
                  <div className="bg-brand-error/10 border border-brand-error/30 text-brand-error px-4 py-3 rounded-lg text-sm backdrop-blur-sm animate-slide-down">
                    {error}
                  </div>
                )}

                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
                  <p className="text-sm text-yellow-800 text-center">
                    <KeyRound className="w-4 h-4 inline mr-1" />
                    Enter one of your backup codes
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-dark-text mb-2">
                    Backup Code
                  </label>
                  <input
                    type="text"
                    value={backupCode}
                    onChange={(e) =>
                      setBackupCode(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8))
                    }
                    className="input text-center text-xl tracking-widest font-mono"
                    placeholder="XXXXXXXX"
                    maxLength={8}
                    required
                    autoFocus
                  />
                  <p className="text-xs text-dark-text-secondary mt-2 text-center">
                    Each backup code can only be used once
                  </p>
                </div>

                <button
                  type="submit"
                  disabled={isLoading || backupCode.length !== 8}
                  className="btn btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? (
                    <LoadingSpinner text="Verifying..." />
                  ) : (
                    "Verify Backup Code"
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setUseBackupCode(false);
                    setBackupCode("");
                    setError("");
                  }}
                  className="w-full text-sm text-dark-text-secondary hover:text-dark-text transition-colors"
                >
                  ← Back to MFA code
                </button>
              </form>
            ) : (
              // MFA Code Form
              <form onSubmit={handleMfaSubmit} className="space-y-6">
                {error && (
                  <div className="bg-brand-error/10 border border-brand-error/30 text-brand-error px-4 py-3 rounded-lg text-sm backdrop-blur-sm animate-slide-down">
                    {error}
                  </div>
                )}

                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
                  <p className="text-sm text-blue-800 text-center">
                    Open Google Authenticator app and enter the 6-digit code
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-dark-text mb-2">
                    MFA Code
                  </label>
                  <input
                    type="text"
                    value={mfaCode}
                    onChange={(e) =>
                      setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                    }
                    className="input text-center text-2xl tracking-widest"
                    placeholder="000000"
                    maxLength={6}
                    required
                    autoFocus
                  />
                  <p className="text-xs text-dark-text-secondary mt-2 text-center">
                    Enter the 6-digit code from Google Authenticator
                  </p>
                </div>

                <button
                  type="submit"
                  disabled={isLoading || mfaCode.length !== 6}
                  className="btn btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? (
                    <LoadingSpinner text="Verifying..." />
                  ) : (
                    "Verify & Sign In"
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setUseBackupCode(true);
                    setMfaCode("");
                    setError("");
                  }}
                  className="w-full text-sm text-dark-text-secondary hover:text-dark-text transition-colors flex items-center justify-center gap-1"
                >
                  <KeyRound className="w-4 h-4" />
                  Use backup code instead
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setMfaRequired(false);
                    setMfaCode("");
                    setError("");
                  }}
                  className="w-full text-sm text-dark-text-secondary hover:text-dark-text transition-colors"
                >
                  ← Back to login
                </button>
              </form>
            )
          ) : (
            /* Regular Login Form */
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Error Message */}
              {error && (
                <div className="bg-brand-error/10 border border-brand-error/30 text-brand-error px-4 py-3 rounded-lg text-sm backdrop-blur-sm animate-slide-down">
                  {error}
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-dark-text mb-2">
                  Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input"
                  placeholder="Enter your email"
                  required
                />
              </div>

              <div>
                <div className="flex justify-between items-center mb-2">
                  <label className="block text-sm font-medium text-dark-text">
                    Password
                  </label>
                  <Link
                    to="/forgot-password"
                    className="text-sm text-brand-primary hover:text-brand-primary-hover transition-colors"
                  >
                    Forgot password?
                  </Link>
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="input pr-10"
                    placeholder="Enter your password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-text-secondary hover:text-dark-text transition-colors"
                    tabIndex={-1}
                  >
                    {showPassword ? (
                      <EyeOff className="w-5 h-5" />
                    ) : (
                      <Eye className="w-5 h-5" />
                    )}
                  </button>
                </div>
              </div>

              {/* Cloudflare Turnstile CAPTCHA */}
              {TURNSTILE_SITE_KEY && (
                <div className="flex justify-center">
                  <Turnstile
                    key={turnstileKey}
                    siteKey={TURNSTILE_SITE_KEY}
                    onSuccess={(token) => setTurnstileToken(token)}
                    onError={() => {
                      setTurnstileToken("");
                      setError("CAPTCHA verification failed. Please try again.");
                    }}
                    onExpire={() => {
                      setTurnstileToken("");
                      toast.error("CAPTCHA expired. Please verify again.");
                    }}
                    theme="dark"
                    size="normal"
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="btn btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <LoadingSpinner text="Signing in..." />
                ) : (
                  "Sign In"
                )}
              </button>
            </form>
          )}

          {/* Google Sign-In - Only show when not in MFA mode */}
          {!mfaRequired && (
            <>
              <div className="mt-6">
                <div className="relative mb-6">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-dark-border"></div>
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-3 bg-dark-card text-dark-text-secondary">
                      Or continue with
                    </span>
                  </div>
                </div>

                <div className="w-full flex justify-center">
                  <GoogleLogin
                    onSuccess={handleGoogleSuccess}
                    onError={handleGoogleError}
                    theme="filled_black"
                    size="large"
                    text="continue_with"
                    shape="rectangular"
                    useOneTap={false}
                  />
                </div>
              </div>

              <div className="mt-6 text-center">
                <p className="text-dark-text-secondary text-sm">
                  Don't have an account?{" "}
                  <Link
                    to="/register"
                    className="text-brand-primary hover:text-brand-primary-hover font-medium transition-colors"
                  >
                    Create Account
                  </Link>
                </p>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
