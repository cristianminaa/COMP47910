package com.cristianmina.comp47910.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Rate Limiting Service for Authentication Brute Force Protection
 * <p>
 * OWASP TOP 10 2021 MITIGATIONS:
 * - A04:2021 Insecure Design - Implements proper rate limiting design
 * - A07:2021 Identification and Authentication Failures - Prevents brute force attacks
 * <p>
 * CWE MITIGATIONS:
 * - CWE-307: Improper Restriction of Excessive Authentication Attempts
 * - CWE-400: Uncontrolled Resource Consumption (via memory management)
 * - CWE-770: Allocation of Resources Without Limits or Throttling
 * <p>
 * SECURITY FEATURES:
 * 1. Progressive Lockout: 5 attempts → 30min lockout → permanent after 10 attempts
 * 2. Time Window Reset: Counters reset after configurable time window (15min default)
 * 3. Dual Tracking: Both per-IP and per-username:IP combination tracking
 * 4. Memory Management: Automatic cleanup prevents DoS via memory exhaustion
 * 5. Configurable Parameters: Environment-based configuration for different environments
 * 6. Comprehensive Logging: All events logged with sanitized input for SIEM integration
 * 7. Admin Override: Emergency unlock capability for legitimate lockouts
 * <p>
 * CONFIGURATION:
 * - security.rate-limiting.max-attempts: Maximum failed attempts before lockout (default: 5)
 * - security.rate-limiting.lockout-duration: Lockout duration in minutes (default: 30)
 * - security.rate-limiting.time-window: Time window for attempt counting (default: 15)
 */
@Service
public class RateLimitingService implements HandlerInterceptor {

  private static final Logger logger = LoggerFactory.getLogger(RateLimitingService.class);
  private static final int EXTENDED_LOCKOUT_HOURS = 24;

  @Autowired
  private SecurityAuditService securityAuditService;

  @Value("${security.rate-limiting.max-attempts:5}")
  private int maxAttempts;

  @Value("${security.rate-limiting.lockout-duration:30}")
  private int lockoutDurationMinutes;

  @Value("${security.rate-limiting.time-window:15}")
  private int timeWindowMinutes;

  private final Map<String, AttemptRecord> attemptRecords = new ConcurrentHashMap<>();
  private final Map<String, LocalDateTime> lockoutUntil = new ConcurrentHashMap<>();

  public RateLimitingService() {
    // Schedule cleanup of expired records every 10 minutes
    ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
    cleanupExecutor.scheduleAtFixedRate(this::cleanupExpiredRecords, 10, 10, TimeUnit.MINUTES);
  }

  /**
   * Records a failed authentication attempt
   */
  public void recordFailedAttempt(String key, String clientIP) {
    LocalDateTime now = LocalDateTime.now();
    AttemptRecord record = attemptRecords.computeIfAbsent(key, k -> new AttemptRecord());

    // Reset counter if time window has passed
    if (record.firstAttempt.isBefore(now.minusMinutes(timeWindowMinutes))) {
      record.reset();
      record.firstAttempt = now;
    }

    record.attemptCount++;
    record.lastAttempt = now;

    // Apply lockout if max attempts exceeded
    if (record.attemptCount >= maxAttempts) {
      LocalDateTime lockoutEnd = now.plusMinutes(lockoutDurationMinutes);
      lockoutUntil.put(key, lockoutEnd);

      logger.warn("SECURITY_ALERT: Account lockout applied for key: {} after {} failed attempts. Lockout until: {}",
              Utilities.sanitizeLogInput(key), record.attemptCount, lockoutEnd);

      // Permanent lockout after 10 failed attempts
      if (record.attemptCount >= 10) {
        LocalDateTime lockoutEndExtended = now.plusHours(EXTENDED_LOCKOUT_HOURS);
        lockoutUntil.put(key, lockoutEndExtended);

        // Send alert to security team
        securityAuditService.logSecurityAlert(
                "EXTENDED_LOCKOUT",
                "HIGH",
                "Account locked for 24 hours after 10 failed attempts",
                key, clientIP, "Possible brute force attack"
        );
      }
    } else {
      logger.warn("Failed authentication attempt for key: {} (attempt {}/{})",
              Utilities.sanitizeLogInput(key), record.attemptCount, maxAttempts);
    }
  }

  /**
   * Records a successful authentication (resets failure counter)
   */
  public void recordSuccessfulAttempt(String key) {
    attemptRecords.remove(key);
    lockoutUntil.remove(key);
    logger.info("Successful authentication for key: {} - failure counters reset",
            Utilities.sanitizeLogInput(key));
  }

  /**
   * Checks if a key is currently blocked
   */
  public boolean isBlocked(String key) {
    // Check for permanent lockout (10+ failures)
    AttemptRecord record = attemptRecords.get(key);
    if (record != null && record.attemptCount >= 10) {
      logger.warn("Access denied for permanently locked key: {}", Utilities.sanitizeLogInput(key));
      return true;
    }

    // Check for temporary lockout
    LocalDateTime lockout = lockoutUntil.get(key);
    if (lockout != null) {
      if (LocalDateTime.now().isBefore(lockout)) {
        long minutesRemaining = ChronoUnit.MINUTES.between(LocalDateTime.now(), lockout);
        logger.warn("Access denied for temporarily locked key: {} ({}min remaining)",
                Utilities.sanitizeLogInput(key), minutesRemaining);
        return true;
      } else {
        // Lockout expired, remove it
        lockoutUntil.remove(key);
        logger.info("Lockout expired for key: {}", Utilities.sanitizeLogInput(key));
      }
    }

    return false;
  }

  /**
   * Gets remaining lockout time in minutes, or 0 if not locked
   */
  public long getRemainingLockoutMinutes(String key) {
    LocalDateTime lockout = lockoutUntil.get(key);
    if (lockout != null && LocalDateTime.now().isBefore(lockout)) {
      return ChronoUnit.MINUTES.between(LocalDateTime.now(), lockout);
    }
    return 0;
  }

  /**
   * Admin function to manually unlock a key (for emergency situations)
   */
  public void manualUnlock(String key, String adminUser) {
    attemptRecords.remove(key);
    lockoutUntil.remove(key);
    logger.warn("ADMIN_ACTION: Manual unlock performed for key: {} by admin: {}",
            Utilities.sanitizeLogInput(key), Utilities.sanitizeLogInput(adminUser));
  }

  /**
   * Cleanup expired records to prevent memory leaks
   * <p>
   * SECURITY MEASURE: Memory Management & DoS Prevention
   * - Prevents unbounded memory growth from accumulating attack records
   * - Removes records older than 24 hours to balance security and performance
   * - Scheduled execution every 10 minutes prevents resource exhaustion
   * - Addresses CWE-400: Uncontrolled Resource Consumption
   */
  private void cleanupExpiredRecords() {
    LocalDateTime cutoff = LocalDateTime.now().minusHours(24);

    int sizeBefore = attemptRecords.size();
    attemptRecords.entrySet().removeIf(entry ->
            entry.getValue().lastAttempt.isBefore(cutoff)
    );
    int cleaned = sizeBefore - attemptRecords.size();

    lockoutUntil.entrySet().removeIf(entry -> entry.getValue().isBefore(LocalDateTime.now()));

    if (cleaned > 0) {
      logger.info("Cleaned up {} expired rate limiting records", cleaned);
    }
  }

  // HandlerInterceptor implementation for web-layer rate limiting
  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    String clientIP = request.getRemoteAddr();
    String requestURI = request.getRequestURI();

    // Apply rate limiting to sensitive endpoints only
    if (requestURI.equals("/") || requestURI.equals("/register") ||
            requestURI.equals("/account") || requestURI.startsWith("/api/")) {

      if (isBlocked(clientIP)) {
        logger.warn("SECURITY_ALERT: Blocked request from rate-limited IP: {} to endpoint: {}",
                Utilities.sanitizeLogInput(clientIP), requestURI);
        response.setStatus(429); // HTTP 429 Too Many Requests
        response.getWriter().write("Too many requests. Please try again later.");
        return false;
      }
    }

    return true;
  }

  private static class AttemptRecord {
    int attemptCount = 0;
    LocalDateTime firstAttempt = LocalDateTime.now();
    LocalDateTime lastAttempt = LocalDateTime.now();

    void reset() {
      attemptCount = 0;
      firstAttempt = LocalDateTime.now();
    }
  }
}