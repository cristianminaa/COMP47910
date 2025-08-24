package com.cristianmina.comp47910.security;

import com.cristianmina.comp47910.authentication.CustomAuthenticationProvider;
import com.cristianmina.comp47910.authentication.CustomWebAuthenticationDetailsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@EnableMethodSecurity
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Autowired
  private CustomUserDetailsService customUserDetailsService;

  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
  }

  @Bean
  public CustomWebAuthenticationDetailsSource authenticationDetailsSource() {
    return new CustomWebAuthenticationDetailsSource();
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
                    .authenticationDetailsSource(authenticationDetailsSource())
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
            .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
            .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; " +
                            "script-src 'self'; " +
                            "style-src 'self'; " +
                            "img-src 'self' data: https://quickchart.io; " +
                            "font-src 'self';"
            ))
            .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000) // 1 year
                    .preload(true)
            )
    );
    return http.build();
  }

  @Bean
  public DaoAuthenticationProvider authProvider() {
    CustomAuthenticationProvider authProvider = new CustomAuthenticationProvider();
    authProvider.setUserDetailsService(customUserDetailsService);
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;
  }

  @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http,
                                                     DaoAuthenticationProvider authProvider) throws Exception {
    return http.getSharedObject(AuthenticationManagerBuilder.class)
            .authenticationProvider(authProvider())
            .build();
  }

}