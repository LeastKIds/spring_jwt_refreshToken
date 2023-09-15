package com.example.jwt.config;

import com.example.jwt.user.User;
import jakarta.persistence.*;
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

    private String token;
    private Date expirationTime;

    private String userEmail;
}
