package com.test.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ChallengeResult {

    private String stateToken;

    private Long stateTokenExpiredAt;

    private TransactionStatus status;

    public enum TransactionStatus {
        SUCCESS, DENY, PASSWORD_ENROLL, PASSWORD_REQUIRED, EMAIL_REQUIRED, MFA_ENROLL, MFA_REQUIRED, MFA_CHALLENGE, MFA_INVALID, PKCE_VERIFICATION_REQUIRED,
    }

}