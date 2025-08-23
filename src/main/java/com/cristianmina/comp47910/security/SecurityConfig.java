package com.cristianmina.comp47910.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@EnableMethodSecurity
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // Enable CSRF protection with secure cookie settings
    http.csrf(csrf -> csrf
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            // Configure authorization
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/css/**", "/js/**", "/images/**", "/.well-known/**").permitAll()
                    .requestMatchers("/", "/register", "/books", "/authors").permitAll()
                    .anyRequest().authenticated()
            )
            .formLogin(form -> form
                    .loginPage("/")
                    .failureUrl("/?error")
                    .defaultSuccessUrl("/books", true)
                    .permitAll()
            )
            .logout(logout -> logout
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/")
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                    .permitAll()
            )
            // Session Management
            .sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .invalidSessionUrl("/")
                    .maximumSessions(1)
                    .maxSessionsPreventsLogin(true)
            )
            // Exception Handling
            .exceptionHandling(exception -> exception
                    .accessDeniedPage("/access-denied")
            );
    http.headers(headers -> headers
            .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
            .xssProtection(HeadersConfigurer.XXssConfig::disable)
            .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; " +
                            "script-src 'self'; " +
                            "style-src 'self'; " +
                            "img-src 'self' data:; " +
                            "font-src 'self';"
            ))
            .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(1800)
            )
    );
    return http.build();
  }

}