from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.utils import timezone
from .models import User, OTPCode, AuditLog, SecurityEvent, MFABackupCode, UserSession


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['username', 'email', 'first_name', 'last_name', 'is_verified', 'mfa_enabled', 'created_at']
    list_filter = ['is_verified', 'mfa_enabled', 'is_staff', 'is_superuser', 'created_at']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering = ['-created_at']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Verification & MFA', {'fields': ('is_verified', 'mfa_enabled')}),
    )


@admin.register(OTPCode)
class OTPCodeAdmin(admin.ModelAdmin):
    list_display = ['user', 'purpose', 'is_used', 'attempts', 'created_at', 'expires_at']
    list_filter = ['purpose', 'is_used', 'created_at']
    search_fields = ['user__username', 'user__email']
    ordering = ['-created_at']
    readonly_fields = ['created_at', 'code']
    
    def has_add_permission(self, request):
        """Prevent manual OTP creation through admin"""
        return False


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'success_badge', 'ip_address', 'device_type', 'created_at']
    list_filter = ['action', 'success', 'device_type', 'created_at']
    search_fields = ['user__username', 'user__email', 'ip_address']
    ordering = ['-created_at']
    readonly_fields = [
        'user', 'action', 'success', 'ip_address', 'user_agent',
        'request_method', 'request_path', 'country', 'city',
        'device_type', 'device_fingerprint', 'metadata', 'created_at'
    ]
    
    fieldsets = (
        ('Event Information', {
            'fields': ('user', 'action', 'success', 'created_at')
        }),
        ('Request Details', {
            'fields': ('request_method', 'request_path', 'ip_address', 'user_agent')
        }),
        ('Device Information', {
            'fields': ('device_type', 'device_fingerprint')
        }),
        ('Location', {
            'fields': ('country', 'city'),
            'classes': ('collapse',)
        }),
        ('Additional Context', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
    )
    
    def success_badge(self, obj):
        """Display success status as colored badge"""
        if obj.success:
            return format_html(
                '<span style="background-color: #28a745; color: white; padding: 3px 10px; '
                'border-radius: 3px; font-weight: bold;">✓ Success</span>'
            )
        return format_html(
            '<span style="background-color: #dc3545; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold;">✗ Failed</span>'
        )
    success_badge.short_description = 'Status'
    
    def has_add_permission(self, request):
        """Prevent manual audit log creation"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Prevent audit log deletion (for compliance)"""
        return request.user.is_superuser  # Only superusers can delete


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'severity_badge', 'event_type', 'status_badge', 
        'user', 'ip_address', 'risk_score', 'alert_sent', 'created_at'
    ]
    list_filter = ['severity', 'event_type', 'status', 'alert_sent', 'created_at']
    search_fields = ['user__username', 'user__email', 'ip_address', 'description']
    ordering = ['-created_at']
    readonly_fields = [
        'event_type', 'severity', 'user', 'ip_address', 
        'description', 'details', 'risk_score', 'alert_sent',
        'alert_sent_at', 'created_at', 'updated_at'
    ]
    
    fieldsets = (
        ('Event Details', {
            'fields': ('event_type', 'severity', 'status', 'risk_score', 'description')
        }),
        ('User & IP', {
            'fields': ('user', 'ip_address')
        }),
        ('Alert Status', {
            'fields': ('alert_sent', 'alert_sent_at')
        }),
        ('Resolution', {
            'fields': ('resolved_by', 'resolved_at', 'resolution_notes'),
            'classes': ('collapse',)
        }),
        ('Additional Details', {
            'fields': ('details',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['mark_as_resolved', 'mark_as_false_positive']
    
    def severity_badge(self, obj):
        """Display severity as colored badge"""
        colors = {
            'low': '#6c757d',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545',
        }
        color = colors.get(obj.severity, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold; text-transform: uppercase;">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = 'Severity'
    
    def status_badge(self, obj):
        """Display status as colored badge"""
        colors = {
            'detected': '#ffc107',
            'investigating': '#17a2b8',
            'resolved': '#28a745',
            'false_positive': '#6c757d',
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    def mark_as_resolved(self, request, queryset):
        """Mark selected events as resolved"""
        for event in queryset:
            event.mark_resolved(request.user, notes='Resolved via admin action')
        self.message_user(request, f"{queryset.count()} event(s) marked as resolved.")
    mark_as_resolved.short_description = "Mark as resolved"
    
    def mark_as_false_positive(self, request, queryset):
        """Mark selected events as false positive"""
        queryset.update(status='false_positive')
        self.message_user(request, f"{queryset.count()} event(s) marked as false positive.")
    mark_as_false_positive.short_description = "Mark as false positive"
    
    def has_add_permission(self, request):
        """Prevent manual security event creation"""
        return False


@admin.register(MFABackupCode)
class MFABackupCodeAdmin(admin.ModelAdmin):
    list_display = ['user', 'is_used', 'used_at', 'used_from_ip', 'created_at']
    list_filter = ['is_used', 'created_at']
    search_fields = ['user__username', 'user__email']
    ordering = ['-created_at']
    readonly_fields = ['user', 'code_hash', 'is_used', 'used_at', 'used_from_ip', 'created_at']
    
    def has_add_permission(self, request):
        """Prevent manual backup code creation"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Only allow deletion by superusers"""
        return request.user.is_superuser




@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'device_name', 'ip_address', 'location_display',
        'is_active', 'is_trusted', 'trust_score', 'is_anomalous',
        'login_at', 'last_activity'
    ]
    list_filter = ['is_active', 'is_trusted', 'is_anomalous', 'device_type', 'login_at']
    search_fields = ['user__username', 'user__email', 'ip_address', 'device_name']
    ordering = ['-last_activity']
    readonly_fields = [
        'user', 'session_key', 'jwt_jti', 'device_fingerprint', 'device_name',
        'device_type', 'browser', 'browser_version', 'os', 'os_version',
        'ip_address', 'country', 'city', 'login_at', 'last_activity',
        'logout_at', 'revoked_at', 'revoked_reason', 'anomaly_reasons'
    ]
    
    fieldsets = (
        ('User & Status', {
            'fields': ('user', 'is_active', 'is_trusted', 'trust_score')
        }),
        ('Device Information', {
            'fields': (
                'device_fingerprint', 'device_name', 'device_type',
                'browser', 'browser_version', 'os', 'os_version'
            )
        }),
        ('Network & Location', {
            'fields': ('ip_address', 'country', 'city')
        }),
        ('Session Details', {
            'fields': ('session_key', 'jwt_jti', 'login_at', 'last_activity', 'logout_at')
        }),
        ('Security', {
            'fields': ('is_anomalous', 'anomaly_reasons', 'revoked_at', 'revoked_reason'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['revoke_sessions', 'trust_sessions']
    
    def location_display(self, obj):
        """Display location as city, country"""
        if obj.city and obj.country:
            return f"{obj.city}, {obj.country}"
        return obj.country or 'Unknown'
    location_display.short_description = 'Location'
    
    def revoke_sessions(self, request, queryset):
        """Revoke selected sessions"""
        count = 0
        for session in queryset.filter(is_active=True):
            session.revoke(reason='admin_action')
            count += 1
        self.message_user(request, f"{count} session(s) revoked.")
    revoke_sessions.short_description = "Revoke selected sessions"
    
    def trust_sessions(self, request, queryset):
        """Mark selected sessions as trusted"""
        count = 0
        for session in queryset:
            session.mark_trusted()
            count += 1
        self.message_user(request, f"{count} session(s) marked as trusted.")
    trust_sessions.short_description = "Mark as trusted"
    
    def has_add_permission(self, request):
        """Prevent manual session creation"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Only superusers can delete sessions"""
        return request.user.is_superuser
