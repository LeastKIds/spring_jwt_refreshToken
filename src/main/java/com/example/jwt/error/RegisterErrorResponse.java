package com.example.jwt.error;

import com.example.jwt.auth.RegisterInterface;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterErrorResponse implements RegisterInterface {
    private String error;
}
