package com.cristianmina.comp47910.security;

import com.cristianmina.comp47910.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
public class CustomUserDetailsService implements UserDetailsService {

  private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);
  
  private final UserRepository userRepository;
  private final RateLimitingService rateLimitingService;

  public CustomUserDetailsService(UserRepository userRepository, RateLimitingService rateLimitingService) {
    this.userRepository = userRepository;
    this.rateLimitingService = rateLimitingService;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    // Get client IP for rate limiting
    String clientIP = getClientIP();
    
    // Check rate limiting for login attempts
    if (rateLimitingService.isBlocked(clientIP)) {
      logger.warn("Login attempts from Client IP {} were blocked. Too many login attempts.", clientIP);
      throw new BadCredentialsException("Too many login attempts. Please try again later.");
    }
    
    logger.debug("Authentication attempt for user from IP: {}", clientIP);

    return userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }
  
  private String getClientIP() {
    try {
      ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
      if (attributes != null && attributes.getRequest() != null) {
        return attributes.getRequest().getRemoteAddr();
      }
    } catch (IllegalStateException e) {
      logger.debug("No request context available");
    }
    return "unknown";
  }
}