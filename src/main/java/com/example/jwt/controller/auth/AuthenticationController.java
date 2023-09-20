package com.example.jwt.controller.auth;

import com.example.jwt.dto.request.auth.AuthenticationRequest;
import com.example.jwt.dto.request.auth.RegisterRequest;
import com.example.jwt.dto.response.auth.AuthenticationTokenResponse;
import com.example.jwt.error.ErrorResponse;
import com.example.jwt.service.auth.AuthenticationService;
import com.example.jwt.type.i.auth.LogoutInterface;
import com.example.jwt.type.i.auth.RefreshTokenInterface;
import com.example.jwt.type.i.auth.RegisterInterface;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<RegisterInterface> register(@Validated @RequestBody RegisterRequest request, Errors errors, HttpServletResponse response) {
        if(errors.hasErrors()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponse.builder().error(errors.toString()).build());
        }

        AuthenticationTokenResponse tokenResponse = service.register(request);

//        // 쿠키 설정
//        Cookie jwtTokenCookie = new Cookie("jwtToken", tokenResponse.getToken());
//        jwtTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
//        jwtTokenCookie.setSecure(true); // HTTPS에서만 사용
//        jwtTokenCookie.setHttpOnly(true); // JS 스크립트에서 액세스 불가
//        jwtTokenCookie.setPath("/");
//
//        Cookie refreshTokenCookie = new Cookie("refreshToken", tokenResponse.getRefreshToken());
//        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
//        refreshTokenCookie.setSecure(true); // HTTPS에서만 사용
//        refreshTokenCookie.setHttpOnly(true); // JS 스크립트에서 액세스 불가
//        refreshTokenCookie.setPath("/");
//
//        // 쿠키를 응답에 추가
//        response.addCookie(jwtTokenCookie);
//        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationTokenResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutInterface> logout(@RequestHeader("Refresh-Token") String refreshToken, @RequestHeader("Authorization") String accessToken ) {
        LogoutInterface response = service.logout(AuthenticationTokenResponse.builder().token(accessToken).refreshToken(refreshToken).build());
        if (response instanceof ErrorResponse) {
            // 에러 응답일 경우
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        // 정상 응답일 경우
        return ResponseEntity.ok(response);
    }

    @PostMapping("/getAccessToken")
    public ResponseEntity<RefreshTokenInterface> getAccessToken(@RequestHeader("Refresh-Token") String refreshToken) {
        RefreshTokenInterface response = service.getAccessToken(refreshToken);

        if (response instanceof ErrorResponse) {
            // 에러 응답일 경우
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        // 정상 응답일 경우
        return ResponseEntity.ok(response);
    }
}
