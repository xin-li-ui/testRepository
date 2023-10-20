package com.test.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class RequestParams {

    private String scope;

    private String clientId;

    private String redirectUri;

    /**
     * request_id
     */
    private String state;

    private String stateToken;

    private String uidUname;

    private String loginHint;

    private String responseType;

    private Boolean useUidCodeAttribute;

}