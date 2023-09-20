package com.example.jwt.config;

import com.example.jwt.user.User;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_refresh")
public class RefreshToken {

    @Id
    @GeneratedValue
    private Long id;

    @NotBlank(message = "token is not blank")
    private String token;

    @NotBlank(message = "expirationTime is not blank")
    private Date expirationTime;

    @NotBlank(message = "userEmail is not blank")
    private String userEmail;
}
