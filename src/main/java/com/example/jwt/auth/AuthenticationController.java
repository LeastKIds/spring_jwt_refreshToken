package com.example.jwt.auth;

import com.example.jwt.error.LogoutErrorResponse;
import com.example.jwt.error.RefreshTokenErrorResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationTokenResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationTokenResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutInterface> logout(@RequestHeader("Refresh-Token") String refreshToken, @RequestHeader("Authorization") String accessToken ) {
        LogoutInterface response = service.logout(AuthenticationTokenResponse.builder().token(accessToken).refreshToken(refreshToken).build());
        if (response instanceof LogoutErrorResponse) {
            // 에러 응답일 경우
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        // 정상 응답일 경우
        return ResponseEntity.ok(response);
    }

    @PostMapping("/getAccessToken")
    public ResponseEntity<RefreshTokenInterface> getAccessToken(@RequestHeader("Refresh-Token") String refreshToken) {
        RefreshTokenInterface response = service.getAccessToken(refreshToken);

        if (response instanceof RefreshTokenErrorResponse) {
            // 에러 응답일 경우
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        // 정상 응답일 경우
        return ResponseEntity.ok(response);
    }
}
