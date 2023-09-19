package com.example.jwt.auth;

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

    @PostMapping("/getAccessToken")
    public ResponseEntity<RefreshTokenInterface> getAccessToken(@RequestHeader("Refresh-Token") String refreshToken) throws Exception {
        RefreshTokenInterface response = service.getAccessToken(refreshToken);

        if (response instanceof RefreshTokenErrorResponse) {
            // 에러 응답일 경우
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        // 정상 응답일 경우
        return ResponseEntity.ok(response);
    }
}
