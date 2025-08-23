package com.cristianmina.comp47910.security;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RateLimitingService {
  private static final int MAX_ATTEMPTS = 3;
  private static final long TIME_WINDOW = 900000; // 15 minutes
  private static final long LOCKOUT_TIME = 3600000; // 1 hour

  private final Map<String, AtomicInteger> failureCount = new ConcurrentHashMap<>();
  private final Map<String, Long> lockoutUntil = new ConcurrentHashMap<>();

  public boolean isBlocked(String key) {
    // Check permanent lockout after 10 failures
    if (failureCount.getOrDefault(key, new AtomicInteger(0)).get() >= 10) {
      // notifySecurityTeam(key);
      return true;
    }

    // Check temporary lockout
    Long lockout = lockoutUntil.get(key);
    return lockout != null && System.currentTimeMillis() < lockout;
  }
}