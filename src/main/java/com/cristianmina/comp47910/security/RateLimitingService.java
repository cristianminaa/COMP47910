package com.cristianmina.comp47910.security;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitingService {
  private final Map<String, List<Long>> attempts = new ConcurrentHashMap<>();
  private static final int MAX_ATTEMPTS = 5;
  private static final long TIME_WINDOW = 300000; // 5 minutes

  public boolean isBlocked(String key) {
    List<Long> timestamps = attempts.getOrDefault(key, new ArrayList<>());
    long now = System.currentTimeMillis();

    // Remove old attempts
    timestamps.removeIf(time -> now - time > TIME_WINDOW);

    if (timestamps.size() >= MAX_ATTEMPTS) {
      return true;
    }

    timestamps.add(now);
    attempts.put(key, timestamps);
    return false;
  }
}