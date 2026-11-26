import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import LoadingSpinner from '../Components/LoadingSpinner';
import {
  Shield, AlertTriangle, Activity, Lock,
  MapPin, Monitor, Calendar, CheckCircle, XCircle
} from 'lucide-react';

const SecurityDashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedFilter, setSelectedFilter] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState(null);
  const [page, setPage] = useState(1);
  const [activityPage, setActivityPage] = useState(1);
  const activityPerPage = 5;
  const navigate = useNavigate();

  useEffect(() => {
    fetchDashboardData();
  }, [selectedFilter, selectedSeverity, page]);

  const fetchDashboardData = async () => {
    try {
      const params = { page, page_size: 10, days: 30 };
      
      if (selectedFilter === 'unresolved') {
        params.resolved = 'false';
      } else if (selectedFilter === 'resolved') {
        params.resolved = 'true';
      }
      
      if (selectedSeverity) {
        params.severity = selectedSeverity;
      }

      const response = await authAPI.getSecurityDashboard(params);
      setDashboardData(response.data);
    } catch (err) {
      if (err.name === 'CanceledError' || err.code === 'ERR_CANCELED') {
        return;
      }
      console.error('Failed to fetch dashboard data:', err);
      setError('Failed to load dashboard data');
      if (err.response?.status === 401) {
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResolveEvent = async (eventId) => {
    if (!confirm('Mark this security event as resolved?')) return;

    try {
      await authAPI.resolveSecurityEvent(eventId, {
        resolution_notes: 'Resolved by user'
      });
      fetchDashboardData();
    } catch (err) {
      console.error('Failed to resolve event:', err);
      setError('Failed to resolve security event');
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      low: 'bg-dark-hover text-dark-text-secondary',
      medium: 'bg-brand-info/20 text-brand-info',
      high: 'bg-brand-warning/20 text-brand-warning',
      critical: 'bg-brand-error/20 text-brand-error',
    };
    return colors[severity] || colors.low;
  };

  const getSeverityIcon = (severity) => {
    if (severity === 'critical' || severity === 'high') {
      return <AlertTriangle className="w-4 h-4" />;
    }
    return <Shield className="w-4 h-4" />;
  };

  if (!dashboardData) {
    return null;
  }

  const { auth_metrics, security_events, session_metrics, recent_activities, events, statistics } = dashboardData;
  const totalPages = events.total_pages;

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
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-dark-text flex items-center">
                <Shield className="w-8 h-8 mr-3 text-brand-primary" />
                Security Monitoring
              </h1>
              <p className="mt-2 text-dark-text-secondary">
                Real-time security insights and threat detection
              </p>
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-6 bg-brand-error/10 border border-brand-error/30 text-brand-error px-4 py-3 rounded-lg backdrop-blur-sm">
            {error}
          </div>
        )}

        {/* Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Authentication Metrics */}
          <div className="bg-dark-surface rounded-lg shadow-dark p-6 border border-dark-border hover:border-brand-primary/50 transition-colors">
            <div className="flex items-center justify-between mb-4">
              <Lock className="w-8 h-8 text-brand-primary" />
              <span className="text-sm text-dark-text-secondary">24h</span>
            </div>
            <h3 className="text-sm font-medium text-dark-text-secondary mb-1">Total Logins</h3>
            <p className="text-3xl font-bold text-dark-text">{auth_metrics.total_logins_24h}</p>
            <p className="text-sm text-brand-error mt-2">
              {auth_metrics.failed_logins_24h} failed
            </p>
          </div>

          {/* Security Events */}
          <div className="bg-dark-surface rounded-lg shadow-dark p-6 border border-dark-border hover:border-brand-warning/50 transition-colors">
            <div className="flex items-center justify-between mb-4">
              <AlertTriangle className="w-8 h-8 text-brand-warning" />
              <span className="text-sm text-dark-text-secondary">Total</span>
            </div>
            <h3 className="text-sm font-medium text-dark-text-secondary mb-1">Security Events</h3>
            <p className="text-3xl font-bold text-dark-text">{security_events.unresolved_events}</p>
            <p className="text-sm text-brand-error mt-2">
              {security_events.critical_events} critical
            </p>
          </div>

          {/* Active Sessions */}
          <div className="bg-dark-surface rounded-lg shadow-dark p-6 border border-dark-border hover:border-brand-success/50 transition-colors">
            <div className="flex items-center justify-between mb-4">
              <Monitor className="w-8 h-8 text-brand-success" />
              <span className="text-sm text-dark-text-secondary">Now</span>
            </div>
            <h3 className="text-sm font-medium text-dark-text-secondary mb-1">Active Sessions</h3>
            <p className="text-3xl font-bold text-dark-text">{session_metrics.active_sessions}</p>
            <p className="text-sm text-brand-success mt-2">
              {session_metrics.trusted_devices} trusted
            </p>
          </div>

          {/* MFA Status */}
          <div className="bg-dark-surface rounded-lg shadow-dark p-6 border border-dark-border hover:border-brand-secondary/50 transition-colors">
            <div className="flex items-center justify-between mb-4">
              <Shield className="w-8 h-8 text-brand-secondary" />
              <span className="text-sm text-dark-text-secondary">MFA</span>
            </div>
            <h3 className="text-sm font-medium text-dark-text-secondary mb-1">Protection Status</h3>
            <p className="text-3xl font-bold text-dark-text">
              {auth_metrics.mfa_enabled ? 'ON' : 'OFF'}
            </p>
            <p className="text-sm text-dark-text-secondary mt-2">
              {auth_metrics.mfa_verifications_7d} verifications (7d)
            </p>
          </div>
        </div>

        {/* Recent Activity */}
        {recent_activities.length > 0 && (
          <div className="bg-dark-surface rounded-lg shadow-dark mb-8 border border-dark-border">
            <div className="p-6 border-b border-dark-border">
              <h2 className="text-xl font-bold text-dark-text flex items-center">
                <Activity className="w-6 h-6 mr-2 text-brand-primary" />
                Recent Activity
              </h2>
            </div>
            <div className="divide-y divide-dark-border">
              {recent_activities
                .slice((activityPage - 1) * activityPerPage, activityPage * activityPerPage)
                .map((activity) => (
                <div key={activity.id} className="p-4 hover:bg-dark-hover transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        {activity.success ? (
                          <CheckCircle className="w-4 h-4 text-brand-success" />
                        ) : (
                          <XCircle className="w-4 h-4 text-brand-error" />
                        )}
                        <span className="font-medium text-dark-text">
                          {activity.action.replace(/_/g, ' ').toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-dark-text-secondary mt-1">
                        From {activity.ip_address} • {new Date(activity.timestamp).toLocaleString()}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            
            {/* Activity Pagination */}
            {recent_activities.length > activityPerPage && (
              <div className="p-4 border-t border-dark-border flex items-center justify-between">
                <button
                  onClick={() => setActivityPage(p => Math.max(1, p - 1))}
                  disabled={activityPage === 1}
                  className="px-4 py-2 border border-dark-border rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-dark-hover text-sm font-medium text-dark-text transition-colors"
                >
                  Previous
                </button>
                <span className="text-sm text-dark-text-secondary">
                  Page {activityPage} of {Math.ceil(recent_activities.length / activityPerPage)}
                </span>
                <button
                  onClick={() => setActivityPage(p => Math.min(Math.ceil(recent_activities.length / activityPerPage), p + 1))}
                  disabled={activityPage === Math.ceil(recent_activities.length / activityPerPage)}
                  className="px-4 py-2 border border-dark-border rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-dark-hover text-sm font-medium text-dark-text transition-colors"
                >
                  Next
                </button>
              </div>
            )}
          </div>
        )}

        {/* Security Events */}
        <div className="bg-dark-surface rounded-lg shadow-dark border border-dark-border">
          <div className="p-6 border-b border-dark-border">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-dark-text">Security Events</h2>
              <div className="flex space-x-2">
                <select
                  value={selectedFilter}
                  onChange={(e) => {
                    setSelectedFilter(e.target.value);
                    setPage(1);
                  }}
                  className="px-3 py-2 bg-dark-bg border border-dark-border rounded-md text-sm text-dark-text focus:outline-none focus:border-brand-primary"
                >
                  <option value="all">All Events</option>
                  <option value="unresolved">Unresolved</option>
                  <option value="resolved">Resolved</option>
                </select>
                <select
                  value={selectedSeverity || ''}
                  onChange={(e) => {
                    setSelectedSeverity(e.target.value || null);
                    setPage(1);
                  }}
                  className="px-3 py-2 bg-dark-bg border border-dark-border rounded-md text-sm text-dark-text focus:outline-none focus:border-brand-primary"
                >
                  <option value="">All Severities</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
            </div>
          </div>

          {loading ? (
            <div className="p-12 flex justify-center">
              <LoadingSpinner />
            </div>
          ) : events.data.length === 0 ? (
            <div className="p-12 text-center text-dark-text-secondary">
              <Shield className="w-12 h-12 mx-auto mb-4 text-dark-muted" />
              <p>No security events found</p>
            </div>
          ) : (
            <>
              <div className="divide-y divide-dark-border">
                {events.data.map((event) => (
                  <div key={event.id} className="p-6 hover:bg-dark-hover transition-colors">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          {getSeverityIcon(event.severity)}
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getSeverityColor(event.severity)}`}>
                            {event.severity.toUpperCase()}
                          </span>
                          <span className="text-sm font-medium text-dark-text">
                            {event.event_type.replace(/_/g, ' ').toUpperCase()}
                          </span>
                          {event.resolved && (
                            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-brand-success/20 text-brand-success">
                              ✓ RESOLVED
                            </span>
                          )}
                        </div>
                        <p className="text-dark-text-secondary mb-2">{event.description}</p>
                        <div className="flex items-center space-x-4 text-sm text-dark-muted">
                          <span className="flex items-center">
                            <MapPin className="w-4 h-4 mr-1" />
                            {event.ip_address}
                          </span>
                          <span className="flex items-center">
                            <Calendar className="w-4 h-4 mr-1" />
                            {new Date(event.created_at).toLocaleString()}
                          </span>
                        </div>
                        {event.resolved && event.resolution_notes && (
                          <div className="mt-2 p-3 bg-brand-success/10 border border-brand-success/30 rounded text-sm text-brand-success">
                            <strong>Resolution:</strong> {event.resolution_notes}
                          </div>
                        )}
                      </div>
                      {!event.resolved && (
                        <button
                          onClick={() => handleResolveEvent(event.id)}
                          className="ml-4 px-4 py-2 bg-brand-success text-white rounded-md hover:bg-brand-success/90 text-sm font-medium transition-colors"
                        >
                          Mark Resolved
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="p-4 border-t border-dark-border flex items-center justify-between">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="px-4 py-2 border border-dark-border rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-dark-hover text-dark-text transition-colors"
                  >
                    Previous
                  </button>
                  <span className="text-sm text-dark-text-secondary">
                    Page {page} of {totalPages}
                  </span>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="px-4 py-2 border border-dark-border rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-dark-hover text-dark-text transition-colors"
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Statistics Charts */}
        {statistics && statistics.top_ips.length > 0 && (
          <div className="mt-8 grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Top IPs */}
            <div className="bg-dark-surface rounded-lg shadow-dark p-6 border border-dark-border">
              <h3 className="text-lg font-bold text-dark-text mb-4">Top IP Addresses (30d)</h3>
              <div className="space-y-3">
                {statistics.top_ips.slice(0, 5).map((ip, idx) => (
                  <div key={idx} className="flex items-center justify-between">
                    <span className="text-sm font-medium text-dark-text">{ip.ip_address}</span>
                    <span className="text-sm text-dark-text-secondary">{ip.count} requests</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Device Distribution */}
            <div className="bg-dark-surface rounded-lg shadow-dark p-6 border border-dark-border">
              <h3 className="text-lg font-bold text-dark-text mb-4">Device Types (30d)</h3>
              <div className="space-y-3">
                {statistics.device_distribution.map((device, idx) => (
                  <div key={idx} className="flex items-center justify-between">
                    <span className="text-sm font-medium text-dark-text capitalize">
                      {device.device_type || 'Unknown'}
                    </span>
                    <span className="text-sm text-dark-text-secondary">{device.count} sessions</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityDashboard;
