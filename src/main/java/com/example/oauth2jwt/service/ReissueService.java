package com.example.oauth2jwt.service;

import com.example.oauth2jwt.entity.RefreshToken;
import com.example.oauth2jwt.jwt.JWTUtil;
import com.example.oauth2jwt.repository.RefreshTokenRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Date;

@Service
public class ReissueService {

    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    public ReissueService(JWTUtil jwtUtil, RefreshTokenRepository refreshTokenRepository) {
        this.jwtUtil = jwtUtil;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public void reissue(HttpServletResponse response ,String refresh) {

        if (refresh == null) {
            throw new RuntimeException("refreshToken null");
        }

        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("refreshToken expired");
        }

        String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {
            throw new RuntimeException("invalid refreshToken");
        }

        Boolean isExist = refreshTokenRepository.existsByRefresh(refresh);

        if (!isExist) {
            throw new RuntimeException("invalid refreshToken");
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        String newAccessToken = jwtUtil.createJwt("access", username, role, 600000L);
        String newRefreshToken = jwtUtil.createJwt("refresh", username, role, 86400000L);

        refreshTokenRepository.deleteByRefresh(refresh);
        saveRefreshToken(username, newRefreshToken, 86400000L);

        response.setHeader("access", newAccessToken);
        response.addCookie(createCookie("refresh", newRefreshToken));

    }

    private void saveRefreshToken(String username, String refreshToken, long expiredMs) {
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshToken refresh = RefreshToken.builder()
                .refresh(refreshToken)
                .username(username)
                .expiration(date.toString())
                .build();

        refreshTokenRepository.save(refresh);
    }


    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24 * 60 * 60);
        //cookie.setSecure(true);
        //cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}

