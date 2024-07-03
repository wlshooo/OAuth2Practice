package com.example.oauth2jwt.service;

import com.example.oauth2jwt.repository.UserRepository;
import com.example.oauth2jwt.dto.GoogleResponse;
import com.example.oauth2jwt.dto.NaverResponse;
import com.example.oauth2jwt.dto.OAuth2Response;
import com.example.oauth2jwt.dto.UserDto;
import com.example.oauth2jwt.entity.User;
import com.example.oauth2jwt.oauth2.CustomOAuth2User;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final String NAVER = "naver";
    private static final String GOOGLE = "google";

    private static final String ROLE_USER = "ROLE_USER";

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        System.out.println(oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if (registrationId.equals(NAVER)) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals(GOOGLE)) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        } else {
            return null;
        }

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        User existUser = userRepository.findByUsername(username);

        if (existUser == null) {
            User user = User.builder()
                    .name(oAuth2Response.getName())
                    .username(username)
                    .email(oAuth2Response.getEmail())
                    .role(ROLE_USER)
                    .build();

            userRepository.save(user);

            UserDto userDto = UserDto.builder()
                    .name(oAuth2Response.getName())
                    .role(ROLE_USER)
                    .username(username).build();

            return new CustomOAuth2User(userDto);
        } else {
            User user = User.builder()
                    .id(existUser.getId())
                    .email(existUser.getEmail())
                    .name(oAuth2Response.getName())
                    .username(existUser.getUsername())
                    .role(existUser.getRole())
                    .build();

            userRepository.save(user);

            UserDto userDto = UserDto.builder()
                    .name(user.getName())
                    .role(user.getRole())
                    .username(user.getUsername()).build();

            return new CustomOAuth2User(userDto);
        }
    }
}
