package com.example.jwt.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.antlr.v4.runtime.misc.NotNull;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest implements RegisterInterface {

    @NotBlank(message = "It must be at least 1 character long.")
    private String firstname;
    @NotBlank(message = "It must be at least 1 character long.")
    private String lastname;

    @Email(message = "Invalid email format.")
    private String email;
    @Size(min = 4, max = 20, message = "The password must be between 4 and 20 characters long.")
    private String password;
}
