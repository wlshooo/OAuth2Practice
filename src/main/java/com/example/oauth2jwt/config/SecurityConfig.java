package com.example.oauth2jwt.config;

import com.example.oauth2jwt.jwt.JWTFilter;
import com.example.oauth2jwt.jwt.JWTUtil;
import com.example.oauth2jwt.oauth2.CustomLogoutFilter;
import com.example.oauth2jwt.oauth2.CustomSuccessHandler;
import com.example.oauth2jwt.repository.RefreshTokenRepository;
import com.example.oauth2jwt.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;

    private final RefreshTokenRepository refreshTokenRepository;

    private final JWTUtil jwtUtil;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService, CustomSuccessHandler customSuccessHandler,
                          JWTUtil jwtUtil,  RefreshTokenRepository refreshTokenRepository) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.customSuccessHandler = customSuccessHandler;
        this.jwtUtil = jwtUtil;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors(corsConfig());

        http
                .csrf((auth) -> auth.disable());

        http
                .formLogin((auth) -> auth.disable());

        http
                .httpBasic((auth) -> auth.disable());

        http
                .addFilterAfter(new JWTFilter(jwtUtil), OAuth2LoginAuthenticationFilter.class);

        http
                .oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig ->
                                userInfoEndpointConfig.userService(customOAuth2UserService)
                        )).successHandler(customSuccessHandler)
                );

        http
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshTokenRepository), LogoutFilter.class);

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/reissue").permitAll()
                        .anyRequest().authenticated());

        http
                .sessionManagement((session) ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }

    private static Customizer<CorsConfigurer<HttpSecurity>> corsConfig() {
        return corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration configuration = new CorsConfiguration();

                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                configuration.setAllowedMethods(Collections.singletonList("*"));
                configuration.setAllowCredentials(true);
                configuration.setAllowedHeaders(Collections.singletonList("*"));
                configuration.setMaxAge(3600L);

                configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                return configuration;
            }
        });
    }
}
