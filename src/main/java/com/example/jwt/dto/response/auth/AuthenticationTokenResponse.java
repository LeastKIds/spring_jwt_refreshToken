package com.example.jwt.dto.response.auth;

import com.example.jwt.type.i.auth.RefreshTokenInterface;
import com.example.jwt.type.i.auth.RegisterInterface;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationTokenResponse implements RefreshTokenInterface, RegisterInterface {
    private String token;
    private String refreshToken;
}
