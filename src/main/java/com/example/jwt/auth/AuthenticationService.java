package com.example.jwt.auth;

import com.example.jwt.config.JwtAuthenticationFilter;
import com.example.jwt.config.JwtService;
import com.example.jwt.config.RefreshToken;
import com.example.jwt.config.RefreshTokenRepository;
import com.example.jwt.error.LogoutErrorResponse;
import com.example.jwt.error.RefreshTokenErrorResponse;
import com.example.jwt.redis.RedisService;
import com.example.jwt.user.Role;
import com.example.jwt.user.User;
import com.example.jwt.user.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ValidationException;
import jakarta.validation.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Set;

import static com.example.jwt.util.AES.AESUtil.decrypt;
import static com.example.jwt.util.AES.AESUtil.encrypt;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;
    private final RedisService redisService;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);


    // validation
    @Autowired
    private Validator validator;


    @Transactional
    public AuthenticationTokenResponse register(RegisterRequest request) {


        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.User)
                .build();

        Set<ConstraintViolation<User>> violations = validator.validate(user);
        if (!violations.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (ConstraintViolation<User> violation : violations) {
                sb.append(violation.getMessage()).append("\n");
            }
            throw new ValidationException(sb.toString());
        }


        repository.save(user);
        var jwtToken = jwtService.generateToken(user);

        // Refresh Token
        var refreshToken = jwtService.generateRefreshToken(user);

        return AuthenticationTokenResponse.builder().token(jwtToken).refreshToken(refreshToken).build();
    }


    // 로그인 역할
    @Transactional(readOnly=true)
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

    @Transactional
    public LogoutInterface logout(AuthenticationTokenResponse tokens) throws RuntimeException{
        String accessToken = tokens.getToken();
        String refreshToken = tokens.getRefreshToken();

        if(!accessToken.startsWith("Bearer ") || !refreshToken.startsWith("Bearer ")) {
            return LogoutErrorResponse.builder().error("Invalid token format").build();
        }
        String accessJwt = accessToken.substring(7);
        String refreshJwt = refreshToken.substring(7);

        String userEmail;
        try {
            userEmail = jwtService.extractRefreshTokenUsername(refreshJwt);
        } catch (ExpiredJwtException e) {
            return LogoutErrorResponse.builder().error("The token is expired").build();
        } catch (JwtException e) {
            return LogoutErrorResponse.builder().error("The token is invalid").build();
        }

        if(refreshTokenRepository.findByToken(encrypt(refreshJwt)).isEmpty()) {
            return LogoutErrorResponse.builder().error("This refresh token is not in the storage").build();
        }



        RefreshToken reToken = refreshTokenRepository.findByToken(encrypt(refreshJwt)).get();
        refreshTokenRepository.delete(reToken);

        Date expirationDate = jwtService.extractExpiration(accessJwt);
        Date currentDate = new Date();
        long differenceInMilliseconds = expirationDate.getTime() - currentDate.getTime();
        if (differenceInMilliseconds < 0) {
            // This means the token has already expired.
            differenceInMilliseconds = 0;
        }

        redisService.setBlackList(encrypt(accessJwt), userEmail, differenceInMilliseconds);
        return LogoutResponse.builder().status(true).build();

    }

    @Transactional(readOnly=true)
    public RefreshTokenInterface getAccessToken(String refreshToken) {
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
            var reGenerateRefreshToken = jwtService.generateRefreshToken(user);
            return AuthenticationTokenResponse.builder().token(accessToken).refreshToken(reGenerateRefreshToken).build();
        } else {
            return RefreshTokenErrorResponse.builder().error("The token values do not match.").build();
        }
    }

}
