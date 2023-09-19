package com.example.jwt.error;

import com.example.jwt.auth.LogoutInterface;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LogoutErrorResponse implements LogoutInterface {
    private String error;
}
