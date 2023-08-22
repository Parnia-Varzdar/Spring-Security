package com.parnia.springsecurity.token;

import com.parnia.springsecurity.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import static com.parnia.springsecurity.token.TokenType.BEARER;
import static jakarta.persistence.EnumType.STRING;
import static jakarta.persistence.FetchType.LAZY;
import static jakarta.persistence.GenerationType.IDENTITY;

@Data
@Entity
@Table
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Token {
    @Id
    @GeneratedValue(strategy = IDENTITY)
    private Long id;
    @ManyToOne(fetch = LAZY)
    @JoinColumn(name = "user_id")
    private User user;
    @Column(unique = true)
    private String token;
    @Enumerated(STRING)
    private TokenType tokenType = BEARER;
    private boolean expired;
    private boolean revoked;
}
