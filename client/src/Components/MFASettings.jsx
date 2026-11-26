import { useState, useEffect } from "react";
import { authAPI, getErrorMessage } from "../services/api";
import toast from "react-hot-toast";
import { Shield, ShieldCheck, X, Download, Copy, RefreshCw, AlertTriangle } from "lucide-react";

export default function MFASettings({ user, onUpdate }) {
  const [showSetup, setShowSetup] = useState(false);
  const [qrCode, setQrCode] = useState("");
  const [secret, setSecret] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showDisableModal, setShowDisableModal] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");
  const [backupCodes, setBackupCodes] = useState([]);
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [backupCodesStatus, setBackupCodesStatus] = useState(null);
  const [showRegenerateModal, setShowRegenerateModal] = useState(false);
  const [regeneratePassword, setRegeneratePassword] = useState("");

  const handleSetupMFA = async () => {
    setIsLoading(true);
    try {
      const response = await authAPI.mfaSetup();
      const { qr_code, secret } = response.data;
      setQrCode(qr_code);
      setSecret(secret);
      setShowSetup(true);
      toast.success("Scan the QR code with Google Authenticator");
    } catch (error) {
      toast.error(getErrorMessage(error));
    } finally {
      setIsLoading(false);
    }
  };

  const handleEnableMFA = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await authAPI.mfaEnable({ code: verificationCode });
      toast.success("MFA enabled successfully!");
      onUpdate(response.data.user);
      
      // Show backup codes
      if (response.data.backup_codes) {
        setBackupCodes(response.data.backup_codes);
        setShowBackupCodes(true);
      }
      
      // Reset setup state
      setShowSetup(false);
      setVerificationCode("");
      setQrCode("");
      setSecret("");
    } catch (error) {
      toast.error(getErrorMessage(error));
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisableMFA = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await authAPI.mfaDisable({ password: disablePassword });
      toast.success("MFA disabled successfully");
      onUpdate(response.data.user);
      // Reset state
      setShowDisableModal(false);
      setDisablePassword("");
      setBackupCodesStatus(null);
    } catch (error) {
      toast.error(getErrorMessage(error));
    } finally {
      setIsLoading(false);
    }
  };

  const fetchBackupCodesStatus = async () => {
    if (!user?.mfa_enabled) return;
    
    try {
      const response = await authAPI.mfaBackupCodesStatus();
      setBackupCodesStatus(response.data);
    } catch (error) {
      console.error("Failed to fetch backup codes status:", error);
    }
  };

  const handleRegenerateBackupCodes = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await authAPI.mfaRegenerateBackupCodes({ 
        password: regeneratePassword 
      });
      setBackupCodes(response.data.backup_codes);
      setShowBackupCodes(true);
      setShowRegenerateModal(false);
      setRegeneratePassword("");
      toast.success("Backup codes regenerated successfully!");
      fetchBackupCodesStatus();
    } catch (error) {
      toast.error(getErrorMessage(error));
    } finally {
      setIsLoading(false);
    }
  };

  const downloadBackupCodes = () => {
    const content = `SecureAuth MFA Backup Codes\n\nGenerated: ${new Date().toLocaleString()}\n\nIMPORTANT: Keep these codes in a safe place. Each code can only be used once.\n\n${backupCodes.join('\n')}\n\n---\nThese codes can be used to access your account if you lose your authenticator device.`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secureauth-backup-codes-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Backup codes downloaded");
  };

  const copyBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join('\n'));
    toast.success("Backup codes copied to clipboard");
  };

  const closeBackupCodesModal = () => {
    setShowBackupCodes(false);
    setBackupCodes([]);
    fetchBackupCodesStatus();
  };

  // Only fetch backup codes status on user interaction, not on mount
  // This prevents unnecessary API calls since status is already in login response

  return (
    <div className="bg-[#1a1a1a] border border-gray-800 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-600/10 flex items-center justify-center">
            {user?.mfa_enabled ? (
              <ShieldCheck className="w-5 h-5 text-green-500" />
            ) : (
              <Shield className="w-5 h-5 text-gray-400" />
            )}
          </div>
          <div>
            <h3 className="font-semibold">Two-Factor Authentication</h3>
            <p className="text-sm text-gray-400">
              {user?.mfa_enabled ? "Enabled" : "Disabled"}
            </p>
          </div>
        </div>
        <span
          className={`px-3 py-1 rounded-full text-xs font-medium ${
            user?.mfa_enabled
              ? "bg-green-600/10 text-green-500 border border-green-600/30"
              : "bg-gray-600/10 text-gray-400 border border-gray-600/30"
          }`}
        >
          {user?.mfa_enabled ? "Enabled" : "Disabled"}
        </span>
      </div>

      <p className="text-sm text-gray-400 mb-4">
        Add an extra layer of security to your account using Google
        Authenticator app.
      </p>

      {/* Backup Codes Status */}
      {user?.mfa_enabled && backupCodesStatus && (
        <div className={`mb-4 p-3 rounded-lg border ${
          backupCodesStatus.warning 
            ? 'bg-yellow-600/10 border-yellow-600/30' 
            : 'bg-blue-600/10 border-blue-600/30'
        }`}>
          <div className="flex items-center gap-2 mb-2">
            {backupCodesStatus.warning && <AlertTriangle className="w-4 h-4 text-yellow-500" />}
            <span className="text-sm font-medium">
              Backup Codes: {backupCodesStatus.unused} / {backupCodesStatus.total} remaining
            </span>
          </div>
          {backupCodesStatus.warning && (
            <p className="text-xs text-yellow-500">
              You're running low on backup codes. Consider regenerating them.
            </p>
          )}
        </div>
      )}

      {!user?.mfa_enabled ? (
        <button
          onClick={handleSetupMFA}
          disabled={isLoading}
          className="w-full bg-blue-600 text-white py-2.5 px-4 rounded-lg font-medium hover:bg-blue-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? "Setting up..." : "Enable MFA"}
        </button>
      ) : (
        <div className="space-y-3">
          <button
            onClick={() => {
              setShowRegenerateModal(true);
              fetchBackupCodesStatus(); // Fetch current status before showing modal
            }}
            className="w-full bg-blue-600/10 text-blue-500 border border-blue-600/30 py-2.5 px-4 rounded-lg font-medium hover:bg-blue-600/20 transition-colors flex items-center justify-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Regenerate Backup Codes
          </button>
          <button
            onClick={() => setShowDisableModal(true)}
            className="w-full bg-red-600/10 text-red-500 border border-red-600/30 py-2.5 px-4 rounded-lg font-medium hover:bg-red-600/20 transition-colors"
          >
            Disable MFA
          </button>
        </div>
      )}

      {/* MFA Setup Modal */}
      {showSetup && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-[#1a1a1a] border border-gray-800 rounded-2xl shadow-xl p-6 max-w-md w-full">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Setup MFA</h3>
              <button
                onClick={() => {
                  setShowSetup(false);
                  setVerificationCode("");
                  setQrCode("");
                  setSecret("");
                }}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-gray-400 mb-3">
                  1. Install Google Authenticator on your phone
                </p>
                <p className="text-sm text-gray-400 mb-3">
                  2. Scan this QR code with the app:
                </p>
                <div className="flex justify-center mb-4 bg-white p-4 rounded-lg">
                  <img src={qrCode} alt="QR Code" className="w-48 h-48" />
                </div>
                <p className="text-xs text-gray-500 mb-2">
                  Or enter this code manually:
                </p>
                <div className="bg-[#0a0a0a] border border-gray-800 p-3 rounded-lg text-center font-mono text-sm break-all">
                  {secret}
                </div>
              </div>

              <form onSubmit={handleEnableMFA}>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  3. Enter the 6-digit code from the app:
                </label>
                <input
                  type="text"
                  value={verificationCode}
                  onChange={(e) =>
                    setVerificationCode(
                      e.target.value.replace(/\D/g, "").slice(0, 6),
                    )
                  }
                  className="w-full px-4 py-3 bg-[#0a0a0a] border border-gray-800 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-2xl tracking-widest text-white"
                  placeholder="000000"
                  maxLength={6}
                  required
                  autoFocus
                />

                <button
                  type="submit"
                  disabled={isLoading || verificationCode.length !== 6}
                  className="w-full mt-4 bg-blue-600 text-white py-3 px-6 rounded-lg font-semibold hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? "Verifying..." : "Enable MFA"}
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Backup Codes Display Modal */}
      {showBackupCodes && backupCodes.length > 0 && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-[#1a1a1a] border border-gray-800 rounded-2xl shadow-xl p-6 max-w-md w-full">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Backup Codes</h3>
              <button
                onClick={closeBackupCodesModal}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="mb-4 p-3 bg-yellow-600/10 border border-yellow-600/30 rounded-lg">
              <p className="text-sm text-yellow-500">
                ⚠️ Save these codes now! Each code can only be used once.
              </p>
            </div>

            <div className="bg-[#0a0a0a] border border-gray-800 rounded-lg p-4 mb-4 max-h-64 overflow-y-auto">
              <div className="grid grid-cols-2 gap-2">
                {backupCodes.map((code, index) => (
                  <div
                    key={index}
                    className="font-mono text-sm text-center py-2 px-3 bg-gray-800 rounded"
                  >
                    {code}
                  </div>
                ))}
              </div>
            </div>

            <div className="flex gap-3">
              <button
                onClick={downloadBackupCodes}
                className="flex-1 bg-blue-600 text-white py-3 px-4 rounded-lg font-semibold hover:bg-blue-700 transition-colors flex items-center justify-center gap-2"
              >
                <Download className="w-4 h-4" />
                Download
              </button>
              <button
                onClick={copyBackupCodes}
                className="flex-1 bg-gray-700 text-white py-3 px-4 rounded-lg font-semibold hover:bg-gray-600 transition-colors flex items-center justify-center gap-2"
              >
                <Copy className="w-4 h-4" />
                Copy
              </button>
            </div>

            <p className="text-xs text-gray-500 text-center mt-4">
              Store these codes in a safe place. You can use them to access your account
              if you lose your authenticator device.
            </p>
          </div>
        </div>
      )}

      {/* Regenerate Backup Codes Modal */}
      {showRegenerateModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-[#1a1a1a] border border-gray-800 rounded-2xl shadow-xl p-6 max-w-md w-full">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Regenerate Backup Codes</h3>
              <button
                onClick={() => {
                  setShowRegenerateModal(false);
                  setRegeneratePassword("");
                }}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="mb-4 p-3 bg-yellow-600/10 border border-yellow-600/30 rounded-lg">
              <p className="text-sm text-yellow-500">
                ⚠️ This will invalidate all existing backup codes.
              </p>
            </div>

            <form onSubmit={handleRegenerateBackupCodes} className="space-y-4">
              <p className="text-sm text-gray-400">
                Enter your password to regenerate backup codes:
              </p>

              <input
                type="password"
                value={regeneratePassword}
                onChange={(e) => setRegeneratePassword(e.target.value)}
                className="w-full px-4 py-3 bg-[#0a0a0a] border border-gray-800 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white"
                placeholder="Enter your password"
                required
                autoFocus
              />

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setShowRegenerateModal(false);
                    setRegeneratePassword("");
                  }}
                  className="flex-1 bg-gray-800 text-gray-300 py-3 px-6 rounded-lg font-semibold hover:bg-gray-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="flex-1 bg-blue-600 text-white py-3 px-6 rounded-lg font-semibold hover:bg-blue-700 transition-colors disabled:opacity-50"
                >
                  {isLoading ? "Regenerating..." : "Regenerate"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Disable MFA Modal */}
      {showDisableModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-[#1a1a1a] border border-gray-800 rounded-2xl shadow-xl p-6 max-w-md w-full">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">Disable MFA</h3>
              <button
                onClick={() => {
                  setShowDisableModal(false);
                  setDisablePassword("");
                }}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <form onSubmit={handleDisableMFA} className="space-y-4">
              <p className="text-sm text-gray-400">
                Enter your password to disable two-factor authentication:
              </p>

              <input
                type="password"
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
                className="w-full px-4 py-3 bg-[#0a0a0a] border border-gray-800 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent text-white"
                placeholder="Enter your password"
                required
                autoFocus
              />

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setShowDisableModal(false);
                    setDisablePassword("");
                  }}
                  className="flex-1 bg-gray-800 text-gray-300 py-3 px-6 rounded-lg font-semibold hover:bg-gray-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="flex-1 bg-red-600 text-white py-3 px-6 rounded-lg font-semibold hover:bg-red-700 transition-colors disabled:opacity-50"
                >
                  {isLoading ? "Disabling..." : "Disable"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
