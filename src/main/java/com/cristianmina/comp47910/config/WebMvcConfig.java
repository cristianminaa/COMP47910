package com.cristianmina.comp47910.config;

import com.cristianmina.comp47910.security.RateLimitingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC Configuration for registering interceptors
 * 
 * SECURITY CONFIGURATION:
 * - Registers RateLimitingService as HandlerInterceptor for request-level rate limiting
 * - Applies to all endpoints for comprehensive protection
 * - Works in conjunction with authentication-level rate limiting in CustomAuthenticationProvider
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Autowired
    private RateLimitingService rateLimitingService;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Register rate limiting interceptor for all requests
        registry.addInterceptor(rateLimitingService)
                .addPathPatterns("/**") // Apply to all endpoints
                .excludePathPatterns("/css/**", "/js/**", "/images/**", "/icons/**", "/favicon.ico"); // Exclude static resources
    }
}