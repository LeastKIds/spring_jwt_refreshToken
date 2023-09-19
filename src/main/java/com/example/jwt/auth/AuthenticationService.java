package com.example.jwt.auth;

import com.example.jwt.config.JwtAuthenticationFilter;
import com.example.jwt.config.JwtService;
import com.example.jwt.config.RefreshTokenRepository;
import com.example.jwt.error.RefreshTokenErrorResponse;
import com.example.jwt.user.Role;
import com.example.jwt.user.User;
import com.example.jwt.user.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.ErrorResponse;

import java.security.SignatureException;

import static com.example.jwt.util.AES.AESUtil.decrypt;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;


    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    public AuthenticationTokenResponse register(RegisterRequest request) {


        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.User)
                .build();


        repository.save(user);
        var jwtToken = jwtService.generateToken(user);

        // Refresh Token
        var refreshToken = jwtService.generateRefreshToken(user);

        return AuthenticationTokenResponse.builder().token(jwtToken).refreshToken(refreshToken).build();
    }


    // 로그인 역할
    public AuthenticationTokenResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                ));
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);

        // Refresh Token
        var refreshToken = jwtService.generateRefreshToken(user);

        return AuthenticationTokenResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public RefreshTokenInterface getAccessToken(String refreshToken) throws RuntimeException {
        // 헤더에 jwt토큰임을 알리는 Bearer가 앞에 존재하는지
        if(!refreshToken.startsWith("Bearer ")) {
            return RefreshTokenErrorResponse.builder().error("Invalid token format").build();
        }
        // Bearer을 제거한 순수 토큰
        String jwt = refreshToken.substring(7);

        String userEmail;
        try {
            userEmail = jwtService.extractRefreshTokenUsername(jwt);
        } catch (ExpiredJwtException e) {
            return RefreshTokenErrorResponse.builder().error("The token is expired").build();
        } catch (JwtException e) {
            return RefreshTokenErrorResponse.builder().error("The token is invalid").build();
        }

        var refresh = refreshTokenRepository.findByUserEmail(userEmail);
        if(refresh.isEmpty()) {
            return RefreshTokenErrorResponse.builder().error("This user does not possess a token.").build();
        }
        if(jwt.equals(decrypt(refresh.get().getToken()))) {
            var user = repository.findByEmail(userEmail)
                    .orElseThrow();
            var accessToken = jwtService.generateToken(user);
            return AuthenticationResponse.builder().token(accessToken).build();
        } else {
            return RefreshTokenErrorResponse.builder().error("The token values do not match.").build();
        }
    }

}
