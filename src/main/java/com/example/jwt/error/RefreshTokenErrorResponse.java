package com.example.jwt.error;

import com.example.jwt.auth.RefreshTokenInterface;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenErrorResponse implements RefreshTokenInterface {
    private String error;
}
