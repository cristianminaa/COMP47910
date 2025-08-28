package com.cristianmina.comp47910.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * Enterprise Security Audit Framework - Centralized Security Event Logging
 * 
 * FRAMEWORK PURPOSE:
 * This service provides a comprehensive, structured approach to security audit logging
 * designed for enterprise-grade applications requiring detailed security monitoring,
 * compliance reporting, and SIEM integration.
 * 
 * CURRENT INTEGRATION STATUS:
 * - ACTIVE: logDataModification() - Used for user registration tracking
 * - FRAMEWORK: Other methods available for future security requirements
 * - SCALABLE: Ready for enterprise security monitoring expansion
 * 
 * DESIGN PHILOSOPHY:
 * The application currently uses effective distributed logging (CustomAuthenticationProvider,
 * RateLimitingService, Controllers) which works well for current needs. This service
 * provides a centralized alternative for organizations requiring:
 * - Unified security event correlation
 * - Compliance audit trails (SOX, GDPR, HIPAA)
 * - SIEM/SOAR integration
 * - Enterprise security monitoring
 * 
 * WHEN TO EXPAND USAGE:
 * - Compliance requirements demand centralized audit logging
 * - SIEM integration requires structured security events
 * - Security team needs correlated event analysis
 * - Application scales beyond current logging approach
 * - Advanced threat detection and response needed
 * 
 * INTEGRATION FLEXIBILITY:
 * Methods can be gradually adopted as security requirements evolve:
 * 1. Start with critical events (data modifications, privilege changes)
 * 2. Add authentication events for centralized analysis
 * 3. Implement suspicious activity detection
 * 4. Enable full enterprise security monitoring
 * 
 * FRAMEWORK VS CURRENT APPROACH:
 * - Current: Distributed logging with good security coverage
 * - Framework: Centralized, structured, correlation-enabled audit trail
 * - Both: Valid approaches for different organizational needs
 * 
 * Implements structured logging for security events with correlation IDs
 */
@Service
public class SecurityAuditService {
    
    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY_AUDIT");
    private static final Logger alertLogger = LoggerFactory.getLogger("SECURITY_ALERTS");
    private static final DateTimeFormatter timestamp = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    /**
     * Log authentication events
     * 
     * FRAMEWORK METHOD: Available for centralized authentication logging
     * Current Status: Not actively used - authentication logging handled by CustomAuthenticationProvider
     * Use Case: Organizations requiring centralized auth event correlation for SIEM integration
     * Integration: Replace scattered auth logging with centralized structured approach
     */
    public void logAuthenticationEvent(String eventType, String username, String clientIP, 
                                     boolean success, String details, Authentication auth) {
        String correlationId = generateCorrelationId();
        
        try {
            MDC.put("correlationId", correlationId);
            MDC.put("eventType", "AUTHENTICATION");
            MDC.put("clientIP", clientIP);
            MDC.put("username", Utilities.sanitizeLogInput(username));
            MDC.put("timestamp", LocalDateTime.now().format(timestamp));
            
            if (success) {
                securityLogger.info("AUTH_SUCCESS - Event: {}, User: {}, IP: {}, Details: {}, Authorities: {}", 
                    eventType, Utilities.sanitizeLogInput(username), clientIP, 
                    Utilities.sanitizeLogInput(details),
                    auth != null ? auth.getAuthorities().toString().replaceAll("[\r\n]", "_") : "none");
            } else {
                securityLogger.warn("AUTH_FAILURE - Event: {}, User: {}, IP: {}, Details: {}", 
                    eventType, Utilities.sanitizeLogInput(username), clientIP, 
                    Utilities.sanitizeLogInput(details));
            }
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * Log resource access events
     * 
     * FRAMEWORK METHOD: Available for detailed resource access tracking
     * Current Status: Framework only - basic resource access handled by AuthorizationService
     * Use Case: Compliance audits requiring detailed resource access trails (CRUD operations)
     * Integration: Track all data access operations for regulatory compliance
     */
    public void logResourceAccess(String resourceType, String resourceId, String operation, 
                                String username, String clientIP, boolean success, String details) {
        String correlationId = generateCorrelationId();
        
        try {
            MDC.put("correlationId", correlationId);
            MDC.put("eventType", "RESOURCE_ACCESS");
            MDC.put("resourceType", resourceType);
            MDC.put("operation", operation);
            MDC.put("clientIP", clientIP);
            MDC.put("username", Utilities.sanitizeLogInput(username));
            MDC.put("timestamp", LocalDateTime.now().format(timestamp));
            
            if (success) {
                securityLogger.info("RESOURCE_SUCCESS - Operation: {} on {} ID: {} by user: {} from IP: {}, Details: {}", 
                    operation, resourceType, resourceId, Utilities.sanitizeLogInput(username), 
                    clientIP, Utilities.sanitizeLogInput(details));
            } else {
                securityLogger.warn("RESOURCE_FAILURE - Operation: {} on {} ID: {} by user: {} from IP: {}, Details: {}", 
                    operation, resourceType, resourceId, Utilities.sanitizeLogInput(username), 
                    clientIP, Utilities.sanitizeLogInput(details));
            }
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * Log security alerts for critical events
     * 
     * FRAMEWORK METHOD: Available for high-priority security event alerting
     * Current Status: Framework only - alerts handled by existing logging infrastructure
     * Use Case: SIEM integration for real-time security incident response
     * Integration: Centralize critical alerts for security operations center (SOC)
     */
    public void logSecurityAlert(String alertType, String severity, String description, 
                               String username, String clientIP, String details) {
        String correlationId = generateCorrelationId();
        
        try {
            MDC.put("correlationId", correlationId);
            MDC.put("eventType", "SECURITY_ALERT");
            MDC.put("alertType", alertType);
            MDC.put("severity", severity);
            MDC.put("clientIP", clientIP);
            MDC.put("username", Utilities.sanitizeLogInput(username));
            MDC.put("timestamp", LocalDateTime.now().format(timestamp));
            
            alertLogger.error("SECURITY_ALERT - Type: {}, Severity: {}, Description: {}, User: {}, IP: {}, Details: {}", 
                alertType, severity, Utilities.sanitizeLogInput(description), 
                Utilities.sanitizeLogInput(username), clientIP, Utilities.sanitizeLogInput(details));
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * Log account lockout events
     * 
     * FRAMEWORK METHOD: Available for centralized lockout event tracking
     * Current Status: Framework only - lockouts handled by RateLimitingService
     * Use Case: Security analytics and pattern analysis for attack correlation
     * Integration: Supplement existing rate limiting with structured audit events
     */
    public void logAccountLockout(String username, String clientIP, int attemptCount, 
                                String lockoutDuration, String lockoutType) {
        String correlationId = generateCorrelationId();
        
        try {
            MDC.put("correlationId", correlationId);
            MDC.put("eventType", "ACCOUNT_LOCKOUT");
            MDC.put("clientIP", clientIP);
            MDC.put("username", Utilities.sanitizeLogInput(username));
            MDC.put("lockoutType", lockoutType);
            MDC.put("timestamp", LocalDateTime.now().format(timestamp));
            
            alertLogger.warn("ACCOUNT_LOCKOUT - User: {}, IP: {}, Type: {}, Attempts: {}, Duration: {}", 
                Utilities.sanitizeLogInput(username), clientIP, lockoutType, attemptCount, lockoutDuration);
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * Log privilege escalation attempts
     * 
     * FRAMEWORK METHOD: Available for detecting unauthorized privilege access
     * Current Status: Framework only - no current privilege escalation scenarios
     * Use Case: Advanced threat detection and insider threat monitoring
     * Integration: Monitor role changes and unauthorized admin access attempts
     */
    public void logPrivilegeViolation(String username, String clientIP, String attemptedAction, 
                                    String requiredRole, String currentRole) {
        String correlationId = generateCorrelationId();
        
        try {
            MDC.put("correlationId", correlationId);
            MDC.put("eventType", "PRIVILEGE_VIOLATION");
            MDC.put("clientIP", clientIP);
            MDC.put("username", Utilities.sanitizeLogInput(username));
            MDC.put("timestamp", LocalDateTime.now().format(timestamp));
            
            alertLogger.error("PRIVILEGE_VIOLATION - User: {} (role: {}) attempted {} requiring {} from IP: {}", 
                Utilities.sanitizeLogInput(username), currentRole, 
                Utilities.sanitizeLogInput(attemptedAction), requiredRole, clientIP);
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * Log data modification events
     * 
     * ACTIVE METHOD: Currently used for user registration audit trail
     * Integration Status: Partial - demonstrates framework usage pattern
     * Use Case: Regulatory compliance requiring complete data change audits
     * Expansion: Can be extended to all CRUD operations across the application
     */
    public void logDataModification(String operation, String tableName, String recordId, 
                                  String username, String clientIP, String oldValues, String newValues) {
        String correlationId = generateCorrelationId();
        
        try {
            MDC.put("correlationId", correlationId);
            MDC.put("eventType", "DATA_MODIFICATION");
            MDC.put("operation", operation);
            MDC.put("tableName", tableName);
            MDC.put("clientIP", clientIP);
            MDC.put("username", Utilities.sanitizeLogInput(username));
            MDC.put("timestamp", LocalDateTime.now().format(timestamp));
            
            securityLogger.info("DATA_MODIFICATION - Operation: {} on {} ID: {} by user: {} from IP: {}, Old: {}, New: {}", 
                operation, tableName, recordId, Utilities.sanitizeLogInput(username), clientIP,
                Utilities.sanitizeLogInput(oldValues), Utilities.sanitizeLogInput(newValues));
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * Log suspicious activity patterns
     * 
     * FRAMEWORK METHOD: Available for advanced threat detection
     * Current Status: Framework only - no anomaly detection currently implemented
     * Use Case: Machine learning-based security analytics and behavioral analysis
     * Integration: Connect with threat intelligence feeds and behavioral baselines
     */
    public void logSuspiciousActivity(String activityType, String description, String username, 
                                    String clientIP, String riskLevel, String evidence) {
        String correlationId = generateCorrelationId();
        
        try {
            MDC.put("correlationId", correlationId);
            MDC.put("eventType", "SUSPICIOUS_ACTIVITY");
            MDC.put("activityType", activityType);
            MDC.put("riskLevel", riskLevel);
            MDC.put("clientIP", clientIP);
            MDC.put("username", Utilities.sanitizeLogInput(username));
            MDC.put("timestamp", LocalDateTime.now().format(timestamp));
            
            alertLogger.warn("SUSPICIOUS_ACTIVITY - Type: {}, Risk: {}, Description: {}, User: {}, IP: {}, Evidence: {}", 
                activityType, riskLevel, Utilities.sanitizeLogInput(description), 
                Utilities.sanitizeLogInput(username), clientIP, Utilities.sanitizeLogInput(evidence));
        } finally {
            MDC.clear();
        }
    }
    
    /**
     * Extract client IP from request with proxy support
     * 
     * FRAMEWORK UTILITY: Available for accurate IP extraction in load-balanced environments
     * Current Status: Framework only - IP extraction handled locally in controllers
     * Use Case: Accurate geolocation and IP-based security analytics
     * Integration: Centralize IP extraction logic for consistent audit logging
     */
    public String getClientIP(HttpServletRequest request) {
        String clientIP = request.getHeader("X-Forwarded-For");
        if (clientIP != null && !clientIP.isEmpty()) {
            clientIP = clientIP.split(",")[0].trim();
        } else {
            clientIP = request.getHeader("X-Real-IP");
            if (clientIP == null || clientIP.isEmpty()) {
                clientIP = request.getRemoteAddr();
            }
        }
        return clientIP != null ? clientIP : "unknown";
    }
    
    /**
     * Generate correlation ID for tracking related security events
     */
    private String generateCorrelationId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}