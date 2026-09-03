package ru.yandex.practicum.oauth0.common.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.ArrayList;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonPropertyOrder({"typ", "iss", "aud", "sub", "client_id", "scopes", "roles", "iat", "exp", "jti", "refresh_id"})
public class TokenClaims {

    private String typ;
    private String iss;
    private String aud;
    private String sub;

    @JsonProperty("client_id")
    private String clientId;

    private List<String> scopes;
    private List<String> roles;
    private Long iat;
    private Long exp;
    private String jti;

    @JsonProperty("refresh_id")
    private String refreshId;

    public String getTyp() {
        return typ;
    }

    public void setTyp(String typ) {
        this.typ = typ;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public List<String> getScopes() {
        return scopes == null ? List.of() : scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes == null ? null : new ArrayList<>(scopes);
    }

    public List<String> getRoles() {
        return roles == null ? List.of() : roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles == null ? null : new ArrayList<>(roles);
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getRefreshId() {
        return refreshId;
    }

    public void setRefreshId(String refreshId) {
        this.refreshId = refreshId;
    }
}
