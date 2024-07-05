package com.example.oauth2jwt.controller;

import com.example.oauth2jwt.service.ReissueService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReissueController {

    private final ReissueService reissueService;

    public ReissueController(ReissueService reissueService) {
        this.reissueService = reissueService;
    }


    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }
        reissueService.reissue(response, refresh);

        return ResponseEntity.status(HttpStatus.OK).body("success");
    }
}
