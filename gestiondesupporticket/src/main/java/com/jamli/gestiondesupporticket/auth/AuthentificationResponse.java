package com.jamli.gestiondesupporticket.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class AuthentificationResponse {
    private String accessToken;
    private String refreshToken;
    private boolean mfaEnabled;
    private String secretImageUri;
}
