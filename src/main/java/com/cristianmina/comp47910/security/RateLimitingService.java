package com.cristianmina.comp47910.security;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Iterator;
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

  // Cleanup expired entries every 10 minutes to prevent memory leak
  @Scheduled(fixedRate = 600000)
  public void cleanupExpiredAttempts() {
    long now = System.currentTimeMillis();
    Iterator<Map.Entry<String, List<Long>>> iterator = attempts.entrySet().iterator();
    
    while (iterator.hasNext()) {
      Map.Entry<String, List<Long>> entry = iterator.next();
      List<Long> timestamps = entry.getValue();
      
      // Remove expired timestamps
      timestamps.removeIf(time -> now - time > TIME_WINDOW);
      
      // Remove empty entries to free memory
      if (timestamps.isEmpty()) {
        iterator.remove();
      }
    }
  }
}