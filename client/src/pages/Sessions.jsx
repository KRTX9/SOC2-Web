import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import LoadingSpinner from '../Components/LoadingSpinner';

const Sessions = () => {
  const [sessions, setSessions] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [revokeLoading, setRevokeLoading] = useState({});
  const navigate = useNavigate();

  const fetchSessions = async () => {
    try {
      setError('');
      const response = await authAPI.getActiveSessions();
      setSessions(response.data.sessions || []);
      setStats(response.data.stats || null);
    } catch (err) {
      if (err.name === 'CanceledError' || err.code === 'ERR_CANCELED') {
        return;
      }
      
      console.error('Failed to fetch sessions:', err);
      setError(err.response?.data?.error || 'Failed to load sessions');
      if (err.response?.status === 401) {
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSessions();
  }, []);

  const handleRevokeSession = async (sessionId) => {
    if (!confirm('Are you sure you want to revoke this session?')) {
      return;
    }

    setRevokeLoading(prev => ({ ...prev, [sessionId]: true }));
    setError('');
    setSuccessMessage('');

    try {
      await authAPI.revokeSession(sessionId);
      setSuccessMessage('Session revoked successfully');
      await fetchSessions();
    } catch (err) {
      console.error('Failed to revoke session:', err);
      setError(err.response?.data?.error || 'Failed to revoke session');
    } finally {
      setRevokeLoading(prev => ({ ...prev, [sessionId]: false }));
    }
  };

  const handleRevokeAll = async () => {
    if (!confirm('Are you sure you want to revoke ALL other sessions? You will remain logged in on this device.')) {
      return;
    }

    setRevokeLoading(prev => ({ ...prev, all: true }));
    setError('');
    setSuccessMessage('');

    try {
      await authAPI.revokeAllSessions();
      setSuccessMessage('All other sessions have been revoked');
      await fetchSessions();
    } catch (err) {
      console.error('Failed to revoke all sessions:', err);
      setError(err.response?.data?.error || 'Failed to revoke all sessions');
    } finally {
      setRevokeLoading(prev => ({ ...prev, all: false }));
    }
  };

  const handleTrustDevice = async (sessionId) => {
    setRevokeLoading(prev => ({ ...prev, [`trust_${sessionId}`]: true }));
    setError('');
    setSuccessMessage('');

    try {
      await authAPI.trustDevice(sessionId);
      setSuccessMessage('Device trusted successfully');
      await fetchSessions();
    } catch (err) {
      console.error('Failed to trust device:', err);
      setError(err.response?.data?.error || 'Failed to trust device');
    } finally {
      setRevokeLoading(prev => ({ ...prev, [`trust_${sessionId}`]: false }));
    }
  };

  const getDeviceIcon = (deviceType) => {
    switch (deviceType?.toLowerCase()) {
      case 'mobile':
        return '📱';
      case 'tablet':
        return '📲';
      case 'pc':
        return '💻';
      default:
        return '🖥️';
    }
  };

  const getBrowserIcon = (browser) => {
    const browserLower = browser?.toLowerCase() || '';
    if (browserLower.includes('chrome')) return '🌐';
    if (browserLower.includes('firefox')) return '🦊';
    if (browserLower.includes('safari')) return '🧭';
    if (browserLower.includes('edge')) return '🌊';
    return '🌐';
  };

  const formatLastActivity = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    
    return date.toLocaleDateString();
  };

  const getTrustScoreBadge = (score) => {
    if (score >= 80) return 'bg-brand-success/20 text-brand-success';
    if (score >= 50) return 'bg-brand-warning/20 text-brand-warning';
    return 'bg-brand-error/20 text-brand-error';
  };

  return (
    <div className="min-h-screen bg-dark-bg py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <button
            onClick={() => navigate('/dashboard')}
            className="text-brand-primary hover:text-brand-primary-hover mb-4 flex items-center transition-colors"
          >
            ← Back to Dashboard
          </button>
          <h1 className="text-3xl font-bold text-dark-text">Active Sessions</h1>
          <p className="mt-2 text-dark-text-secondary">
            Manage your active sessions and monitor login activity
          </p>
        </div>

        {/* Messages */}
        {error && (
          <div className="mb-6 bg-brand-error/10 border border-brand-error/30 text-brand-error px-4 py-3 rounded-lg backdrop-blur-sm">
            {error}
          </div>
        )}
        {successMessage && (
          <div className="mb-6 bg-brand-success/10 border border-brand-success/30 text-brand-success px-4 py-3 rounded-lg backdrop-blur-sm">
            {successMessage}
          </div>
        )}
        {stats?.security_warning && (
          <div className="mb-6 bg-brand-warning/10 border-2 border-brand-warning/30 rounded-lg p-4">
            <div className="flex items-start">
              <div className="text-3xl mr-3">⚠️</div>
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-brand-warning mb-2">
                  {stats.security_warning.message}
                </h3>
                <ul className="list-disc list-inside text-sm text-dark-text-secondary space-y-1">
                  {stats.security_warning.patterns.map((pattern, idx) => (
                    <li key={idx}>{pattern}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-dark-surface rounded-lg shadow-dark p-6 border border-dark-border">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-dark-text-secondary">Active Sessions</p>
                  <p className="text-3xl font-bold text-dark-text">{stats.total_sessions || 0}</p>
                </div>
                <div className="text-4xl">🔐</div>
              </div>
            </div>
            <div className="bg-dark-surface rounded-lg shadow-dark p-6 border border-dark-border">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-dark-text-secondary">Trusted Devices</p>
                  <p className="text-3xl font-bold text-brand-success">{stats.trusted_devices || 0}</p>
                </div>
                <div className="text-4xl">✅</div>
              </div>
            </div>
            <div className="bg-dark-surface rounded-lg shadow-dark p-6 border border-dark-border">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-dark-text-secondary">Anomalous Sessions</p>
                  <p className="text-3xl font-bold text-brand-error">{stats.anomalous_sessions || 0}</p>
                </div>
                <div className="text-4xl">⚠️</div>
              </div>
            </div>
          </div>
        )}

        {/* Revoke All Button */}
        {sessions.length > 1 && (
          <div className="mb-6 flex justify-end">
            <button
              onClick={handleRevokeAll}
              disabled={revokeLoading.all}
              className="bg-brand-error text-white px-6 py-2 rounded-md hover:bg-brand-error/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center transition-colors"
            >
              {revokeLoading.all ? (
                <>
                  <LoadingSpinner />
                  <span className="ml-2">Revoking...</span>
                </>
              ) : (
                <>
                  🚫 Revoke All Other Sessions
                </>
              )}
            </button>
          </div>
        )}

        {/* Sessions List */}
        {sessions.length === 0 ? (
          <div className="bg-dark-surface rounded-lg shadow-dark p-12 text-center border border-dark-border">
            <p className="text-dark-text-secondary text-lg">No active sessions found</p>
          </div>
        ) : (
          <div className="space-y-4">
            {sessions.map((session) => (
              <div
                key={session.id}
                className={`bg-dark-surface rounded-lg shadow-dark p-6 border ${
                  session.is_current ? 'ring-2 ring-brand-primary border-brand-primary' : 'border-dark-border'
                } ${session.is_anomalous ? 'border-brand-error/50' : ''} hover:border-brand-primary/50 transition-colors`}
              >
                {/* Session Header */}
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-start space-x-4">
                    <div className="text-5xl">
                      {getDeviceIcon(session.device_type)}
                    </div>
                    <div>
                      <div className="flex items-center space-x-2 flex-wrap">
                        <h3 className="text-lg font-semibold text-dark-text">
                          {session.device_name || 'Unknown Device'}
                        </h3>
                        {session.is_current && (
                          <span className="bg-brand-primary/20 text-brand-primary text-xs font-semibold px-2.5 py-0.5 rounded">
                            Current Session
                          </span>
                        )}
                        {session.is_trusted && (
                          <span className="bg-brand-success/20 text-brand-success text-xs font-semibold px-2.5 py-0.5 rounded">
                            ✓ Trusted
                          </span>
                        )}
                        {session.is_anomalous && (
                          <span className="bg-brand-error/20 text-brand-error text-xs font-semibold px-2.5 py-0.5 rounded">
                            ⚠️ Anomalous
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-dark-text-secondary mt-1">
                        {getBrowserIcon(session.browser)} {session.browser} on {session.os}
                      </p>
                      <p className="text-xs text-dark-muted mt-1">
                        Last active: {formatLastActivity(session.last_activity)}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getTrustScoreBadge(session.trust_score)}`}>
                      Trust Score: {session.trust_score}
                    </span>
                  </div>
                </div>

                {/* Session Details */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4 text-sm">
                  <div>
                    <p className="text-dark-text-secondary">
                      <span className="font-medium text-dark-text">IP Address:</span> {session.ip_address || 'Unknown'}
                    </p>
                    <p className="text-dark-text-secondary">
                      <span className="font-medium text-dark-text">Location:</span> {session.location_display || 'Unknown'}
                    </p>
                  </div>
                  <div>
                    <p className="text-dark-text-secondary">
                      <span className="font-medium text-dark-text">Created:</span> {new Date(session.created_at).toLocaleString()}
                    </p>
                    <p className="text-dark-text-secondary">
                      <span className="font-medium text-dark-text">Expires:</span> {new Date(session.expires_at).toLocaleString()}
                    </p>
                  </div>
                </div>

                {/* Anomaly Reasons */}
                {session.is_anomalous && session.anomaly_reasons && session.anomaly_reasons.length > 0 && (
                  <div className="mb-4 bg-brand-error/10 border border-brand-error/30 rounded p-3">
                    <p className="text-sm font-medium text-brand-error mb-2">Security Alerts:</p>
                    <ul className="list-disc list-inside text-sm text-dark-text-secondary space-y-1">
                      {session.anomaly_reasons.map((reason, idx) => (
                        <li key={idx}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Actions */}
                {!session.is_current && (
                  <div className="flex space-x-3">
                    {!session.is_trusted && (
                      <button
                        onClick={() => handleTrustDevice(session.id)}
                        disabled={revokeLoading[`trust_${session.id}`]}
                        className="flex-1 bg-brand-success text-white px-4 py-2 rounded-md hover:bg-brand-success/90 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium transition-colors"
                      >
                        {revokeLoading[`trust_${session.id}`] ? (
                          <div className="flex items-center justify-center">
                            <LoadingSpinner />
                            <span className="ml-2">Trusting...</span>
                          </div>
                        ) : (
                          '✓ Trust This Device'
                        )}
                      </button>
                    )}
                    <button
                      onClick={() => handleRevokeSession(session.id)}
                      disabled={revokeLoading[session.id]}
                      className="flex-1 bg-brand-error text-white px-4 py-2 rounded-md hover:bg-brand-error/90 disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium transition-colors"
                    >
                      {revokeLoading[session.id] ? (
                        <div className="flex items-center justify-center">
                          <LoadingSpinner />
                          <span className="ml-2">Revoking...</span>
                        </div>
                      ) : (
                        '🚫 Revoke Session'
                      )}
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default Sessions;
