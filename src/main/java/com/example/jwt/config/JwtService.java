package com.example.jwt.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static com.example.jwt.util.AES.AESUtil.encrypt;

@Service
@AllArgsConstructor
public class JwtService {
    private static final String SECRET_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCS8qEOxD59M74fIQROH2YoJ1uPn8AmU8zWdsSCxj4byaO0z80RA18UCypLHmkZNjR5HyFS3M9LKUEQMR8P3clc7tSz1YTbmNACcxU3XR2e5dOeW/MvptgJMlWpDP5OZ7FfF8SPBlwlp7tSLMWjVUzkHAexdp6vn6tMe28zvn0B9eb51K+T18sRZfMLdWx0sRJrBB/7fK2dZRTUDgapKVcmc3sTxAm4dQMmnkwr9ttAUCX6Zpa5pP5j+Rm6ujEEADAczg4t87GpTnckbU6blEJlIcrqnUGWlbdoq9NZR+XWbeH8lgT8sRaTZcmy4O5IFHYT2tvSyFTNMncnPQTaRcxvAgMBAAECggEAWAnFNHOefKRjY4MEcUmeirAJyyKKnGvYbST61t6ulzdXPRzCX08Fx5xo2lh93vz6sxZTgLGKAB3XPTwwv/DAk00DYjqqPmZvOQh5zZGcDXbkMhwktoffJqNhbsa6FX9KZQ54VLgavPSg5bqtLg4M4x1n/opyyAWBO3E4TmfxvRoNu/8d2rlJ+cLeLqPZiCMWHqjgFx0KQcUlQVe6neXDS1zK7NFp8EnG9JGdHweYBsU3DdAw4yvRg/0AudZwBzONF4YfZuXAYZiHO/WwU7pdMaQPGexXTqtIg5vd+uDNPeoMczptglgD8CYbymT3bxk+YvKXK0yycb1fAEM2C557AQKBgQDEP9wfx89tvls5r11UwQNCRrrT0Wqe1i8NZtIrDsiJZz/Nb6WdYsnXqmWXCbEyesimD0xjpCSv9V8RVwE6Lq/9SgVzm/RSyiNKtHGtrD1Erqijl5GBoCcZJoCOiAB/R4V5nkWUF4A3hOYWVxQf+B7V/K1krbkg5M9HFdFOlA23hQKBgQC/sBTEn3ESFxQqU/GmVTAD33En3Hm+CusU8igQP2i5ZbH32pj0Wyxf3Ul98dZN64UCnGXxp1x+hkq4H44g/mRN3812LqbcN0KxNPVKFGhoClaDw72bRlLtPExumwps02Xw1gc0M8/QMKZt+5zOmUqpgQ41OoYkRSDwqECWQX7EYwKBgHWiodwa9WefFye4yoUnPUDZDNwzR2n2kTXDUG+m6OYUEdae+fMhaEPyS/sBQEo191gzC2Me3S7sMhQ+xumNWsjFOgdWkFmf+Q+qogmsmP02hLeq/vloeodE4QKO211wDb4c9TAT9jNRYmo5wEJ5hGJYl8clqzbgcK73kQM9FAvRAoGAJCAMGe4ugglFbKC7VuyRCvnOOoPrkaw/F4h3knBQzTfkLWDOGKciGsL6ebjc+XxcadyNvdgbr2ChrkeMIp2uy5pU/2PVYIUtlXX0kEx+TLU+DsER97RuJnWJtgKUGWRRvuynGOh2zraMdwfHSoxLLNy8j72C0E0S4yfiXC7ltB8CgYEAmrswkxlS1Lna6Og2Ea9Ih0gZFT9abvc8UJg6aX1RI6LWsoOTRrsy6etJXh+NZU7+0PVFV4fXwASx0Uayp9hwYkLPVyPOmgINwNnEiyoCwpygvHxkFTOc4vweWRyoTUDPge5/Ua6Q81e/pwr5yRr7SUWx7ps+NOfr6b5aYJoC/PA=";
    private static final String REFRESH_TOKEN_KEY = "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDhdpH7ztoZwENllRZLKX/JZ2CTOuCKETR4lz4zKwdTQ5kH/CKhXFjPZKND9614cb8L3GRzmlL5dwpCMPCbrFJ7dUO4RvZnOjl5g3T3kjliTM152iL09kcdgPwD9GGEvvF41Ux4lVQJv1JVqZiOrcr0m9e2jgJP+V1L17QLOsdGINGEEE3afpcu5xzr96D63F3u7liTneu48+OHFHpaA6LYiG3Zu33HryXMDyPKoqPXvKmFi1eKvRJzHQF60m1mCJ1Uw7CvfMKLyiG/N+3kMHSV/V1PQ0lfwIS2YoJd9ilemIly8+pwXRHVB6tIUMlkr01BffgY/aOoSN4jvXy90f/dAgMBAAECggEBALV1gqTRpMOY9CVryleP/OMSKq4UcudsVXjA8TSpauneu+mrSgvokSnJ64UmcB1CHuri5I4OJL3WyxDe5qfEF1Z52JkVs/b864ka/ibLLxgojC+IGx5goHfkefCM3XfDXgFMWpGqTcrSiuea6cfbpD8etoyc2suW/TmvT57CHeQXvsCMpE3epdBS3FxixZIRSTLt0aBKzMbwSa8XHGKZe7ZjlghGynl5hS6KatiJxkn/XcjXSRI3G0W7rJsstIe6WSicsiHIYF7+j532ftyytNxcuGtM5coWY1AoyAIeBPqMX+qOgFblRNH92feZeoWZF77YUYoOGEOpstSdJM9VbQECgYEA+hSbB9Lvb9B6hoZ2L8Qjylx2cJX3G1N5me3Su+gXEEqqNLdgJILgwmLA0FUAkjywzsZomdrRJHmFeTUdHB2w8luVnKW6YR3exVL/63P0ORsuwfo9AWaUxMoe5GZgZ7LKZjRfc2XIbJuLowputehOSRU6KVB5l7Lh3n3TSoAWiH0CgYEA5szK+LskUjrTYVUiYf+8qqdzIy7VmxZe+p3dHXUgxk/dIktnPudPNJNFVKiU4f6SosQUvnnS/rwVnRHvXb6AEEyLJPbx4qkMnSfN1NvWnOwMvKBuV++3LDrUz+Apf/jaHR1o0YWx87BhitJS3Ca8pJRmcKnTCjZo3CYB1dk8UuECgYEAzVTx3cCx28r/b0kj7SBMirDUhqh7VjJ524tLxgFQPo4vpk0SYagcRz6yNdw1Nd0jBwQdioYBxsMIdnbHyfgO+097Tj09BNRzvuzhOD/ivKi3AYonYOkLKXETYFE2wq4oRTanUKa3o4UrZ9j/AdkVvifxs05iJ842ampBfCAjYDkCgYEAlc76NGbslX9fcz8aWTfxE2grYPvmZIspzUyomJVNV8vBAqCk/HyRudOZ3fCq6uId9g6GVHiozvXwpYpdr6CWaX31l2G+8du+t0d94Btt+19wiQMtfGC5qbjqJ6Ad79XsZZeQUOeR8VZcigopBIMUUVOOBrUEqg1VFQiKim8+K6ECgYEAjsL7lL/VXLi5vjRR8HVzG4dsj+crlsTin2d8HpbNzEPWslSGKsqAKAr/hlDP5clYmZnFbOSvOIF29JrgfuX8BXFiUdeiRh0P90luXtHEiFl/2n2S1XWkjcteyxol3GTp4HMcRgyrCSGU4IlS/arNWFxAOs0NLeLPhuMKZzCtynQ=";

    private Claims extractAllClaims(String token) {
        return  Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode((SECRET_KEY));
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpriation(token).before(new Date());
    }

    private Date extractExpriation(String token) {
        return extractClaims(token, Claims::getExpiration);
    }



    // Refresh Token

    private final RefreshTokenRepository refreshTokenRepository;


    public String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        var date = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 14);

        String refreshToken = Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(date)
                .signWith(getRefreshTokenSignInKey(), SignatureAlgorithm.HS256)
                .compact();

       var rf = RefreshToken.builder()
               .token(encrypt(refreshToken))
               .userEmail(userDetails.getUsername())
               .expirationTime(date)
               .build();

        refreshTokenRepository.save(rf);

        return refreshToken;
    }
    public String generateRefreshToken(UserDetails userDetails) {
        return generateRefreshToken(new HashMap<>(), userDetails);
    }

    private Key getRefreshTokenSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode((REFRESH_TOKEN_KEY));
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractRefreshTokenUsername(String token) throws RuntimeException {
        return extractRefreshTokenClaims(token, Claims::getSubject);
    }

    public <T> T extractRefreshTokenClaims(String token, Function<Claims, T> claimsResolver) throws RuntimeException {
        final Claims claims = extractRefreshTokenAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractRefreshTokenAllClaims(String token) throws RuntimeException{

        return Jwts
                .parserBuilder()
                .setSigningKey(getRefreshTokenSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }
}
