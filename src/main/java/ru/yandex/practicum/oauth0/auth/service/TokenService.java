package ru.yandex.practicum.oauth0.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.config.AuthProperties;
import ru.yandex.practicum.oauth0.auth.domain.ClientEntity;
import ru.yandex.practicum.oauth0.auth.domain.RefreshTokenEntity;
import ru.yandex.practicum.oauth0.auth.domain.RevocationEntity;
import ru.yandex.practicum.oauth0.auth.domain.UserEntity;
import ru.yandex.practicum.oauth0.auth.repo.ClientRepository;
import ru.yandex.practicum.oauth0.auth.repo.RefreshTokenRepository;
import ru.yandex.practicum.oauth0.auth.repo.RevocationRepository;
import ru.yandex.practicum.oauth0.auth.repo.UserRepository;
import ru.yandex.practicum.oauth0.auth.web.dto.IntrospectResponse;
import ru.yandex.practicum.oauth0.auth.web.dto.RevokeRequest;
import ru.yandex.practicum.oauth0.auth.web.dto.RevokeResponse;
import ru.yandex.practicum.oauth0.auth.web.dto.TokenRequest;
import ru.yandex.practicum.oauth0.auth.web.dto.TokenResponse;
import ru.yandex.practicum.oauth0.common.crypto.PasswordHasher;
import ru.yandex.practicum.oauth0.common.time.TimeProvider;
import ru.yandex.practicum.oauth0.common.token.TokenClaims;
import ru.yandex.practicum.oauth0.common.token.TokenCodec;
import ru.yandex.practicum.oauth0.common.token.TokenException;
import ru.yandex.practicum.oauth0.common.token.TokenKind;
import ru.yandex.practicum.oauth0.common.token.TokenValidator;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    public static final String GRANT_PASSWORD = "password";
    public static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
    public static final String GRANT_REFRESH_TOKEN = "refresh_token";

    private final UserRepository users;
    private final ClientRepository clients;
    private final RefreshTokenRepository refreshTokens;
    private final RevocationRepository revocations;
    private final ScopeResolver scopeResolver;
    private final RefreshChainRevoker chainRevoker;
    private final AuditService audit;
    private final TokenCodec codec;
    private final TokenValidator validator;
    private final PasswordHasher passwords;
    private final TimeProvider time;
    private final AuthProperties props;

    public TokenService(UserRepository users,
                        ClientRepository clients,
                        RefreshTokenRepository refreshTokens,
                        RevocationRepository revocations,
                        ScopeResolver scopeResolver,
                        RefreshChainRevoker chainRevoker,
                        AuditService audit,
                        TokenCodec codec,
                        TokenValidator validator,
                        PasswordHasher passwords,
                        TimeProvider time,
                        AuthProperties props) {
        this.users = users;
        this.clients = clients;
        this.refreshTokens = refreshTokens;
        this.revocations = revocations;
        this.scopeResolver = scopeResolver;
        this.chainRevoker = chainRevoker;
        this.audit = audit;
        this.codec = codec;
        this.validator = validator;
        this.passwords = passwords;
        this.time = time;
        this.props = props;
    }

    @Transactional
    public TokenResponse issue(TokenRequest request) {
        String grantType = request.grantType();
        if (grantType == null || grantType.isBlank()) {
            throw OAuthException.badRequest("invalid_request", "grant_type is required");
        }
        return switch (grantType) {
            case GRANT_PASSWORD -> issueByPassword(request);
            case GRANT_CLIENT_CREDENTIALS -> issueByClientCredentials(request);
            case GRANT_REFRESH_TOKEN -> throw OAuthException.badRequest("invalid_request",
                    "use POST /token/refresh for the refresh_token grant");
            default -> throw OAuthException.badRequest("unsupported_grant_type",
                    "unknown grant_type: " + grantType);
        };
    }

    private TokenResponse issueByPassword(TokenRequest request) {
        ClientEntity client = authenticateClient(request.clientId(), request.clientSecret());
        requireGrant(client, GRANT_PASSWORD);

        if (isBlank(request.username()) || isBlank(request.password())) {
            throw OAuthException.badRequest("invalid_request", "username and password are required");
        }

        UserEntity user = users.findByUsername(request.username()).orElse(null);
        if (user == null || !passwords.matches(request.password(), user.getPasswordHash())) {
            audit.failure("token.password", client.getClientId(), null, "invalid user credentials");
            throw OAuthException.unauthorized("invalid_grant", "invalid username or password");
        }
        if (!user.isEnabled()) {
            audit.failure("token.password", client.getClientId(), user.getUserId(), "user is disabled");
            throw OAuthException.forbidden("access_denied", "user is disabled");
        }

        List<String> granted = scopeResolver.resolve(request.scopes(),
                scopeResolver.scopesOfUser(user), client.getAllowedScopes());
        List<String> roles = new ArrayList<>(user.getRoles());

        long now = time.nowEpochSeconds();
        String accessToken = codec.encode(accessClaims(client, user.getUserId(), granted, roles, now));
        IssuedRefresh refresh = issueRefreshToken(client, user.getUserId(), granted, now);

        audit.success("token.password", client.getClientId(), user.getUserId(),
                "scopes=" + ScopeResolver.asString(granted));
        return TokenResponse.of(accessToken, refresh.token(), props.getAccessTtlSec(),
                ScopeResolver.asString(granted));
    }

    private TokenResponse issueByClientCredentials(TokenRequest request) {
        ClientEntity client = authenticateClient(request.clientId(), request.clientSecret());
        requireGrant(client, GRANT_CLIENT_CREDENTIALS);

        List<String> granted = scopeResolver.resolve(request.scopes(),
                client.getAllowedScopes(), client.getAllowedScopes());

        long now = time.nowEpochSeconds();
        String accessToken = codec.encode(
                accessClaims(client, client.getClientId(), granted, List.of("service"), now));

        audit.success("token.client_credentials", client.getClientId(), null,
                "scopes=" + ScopeResolver.asString(granted));
        return TokenResponse.of(accessToken, null, props.getAccessTtlSec(),
                ScopeResolver.asString(granted));
    }

    @Transactional
    public TokenResponse refresh(TokenRequest request) {
        ClientEntity client = authenticateClient(request.clientId(), request.clientSecret());
        requireGrant(client, GRANT_REFRESH_TOKEN);

        if (isBlank(request.refreshToken())) {
            throw OAuthException.badRequest("invalid_request", "refresh_token is required");
        }

        long now = time.nowEpochSeconds();
        TokenClaims claims = decodeRefreshToken(request.refreshToken(), client.getClientId(), now);

        RefreshTokenEntity record = refreshTokens.findById(claims.getRefreshId())
                .orElseThrow(() -> {
                    audit.failure("token.refresh", client.getClientId(), null, "refresh id is unknown");
                    return OAuthException.unauthorized("invalid_grant", "refresh token is not recognized");
                });

        if (!record.getClientId().equals(client.getClientId())) {
            audit.failure("token.refresh", client.getClientId(), record.getUserId(),
                    "refresh token belongs to another client");
            throw OAuthException.unauthorized("invalid_grant", "refresh token was issued to another client");
        }
        if (record.isRevoked()) {
            audit.failure("token.refresh", client.getClientId(), record.getUserId(), "refresh token revoked");
            throw OAuthException.unauthorized("invalid_grant", "refresh token has been revoked");
        }
        if (record.isRotated()) {
            chainRevoker.revokeFamily(record.getRefreshId(), now);
            audit.failure("token.refresh", client.getClientId(), record.getUserId(),
                    "reuse of a rotated refresh token, chain revoked");
            throw OAuthException.conflict("invalid_grant",
                    "refresh token has already been used; the token family was revoked");
        }
        if (record.getExpiresAt() < now) {
            audit.failure("token.refresh", client.getClientId(), record.getUserId(), "refresh token expired");
            throw OAuthException.unauthorized("invalid_grant", "refresh token has expired");
        }

        UserEntity user = users.findById(record.getUserId())
                .orElseThrow(() -> OAuthException.unauthorized("invalid_grant", "user no longer exists"));
        if (!user.isEnabled()) {
            throw OAuthException.forbidden("access_denied", "user is disabled");
        }

        List<String> previous = ScopeResolver.parse(record.getScopes());
        List<String> granted = scopeResolver.resolve(previous,
                scopeResolver.scopesOfUser(user), client.getAllowedScopes());
        List<String> roles = new ArrayList<>(user.getRoles());

        String accessToken = codec.encode(accessClaims(client, user.getUserId(), granted, roles, now));
        IssuedRefresh replacement = issueRefreshToken(client, user.getUserId(), granted, now);

        record.setRotated(true);
        record.setReplacedBy(replacement.refreshId());
        refreshTokens.save(record);

        audit.success("token.refresh", client.getClientId(), user.getUserId(),
                "rotated " + record.getRefreshId() + " -> " + replacement.refreshId());
        return TokenResponse.of(accessToken, replacement.token(), props.getAccessTtlSec(),
                ScopeResolver.asString(granted));
    }

    @Transactional
    public RevokeResponse revoke(RevokeRequest request) {
        if (isBlank(request.token())) {
            throw OAuthException.badRequest("invalid_request", "token is required");
        }

        long now = time.nowEpochSeconds();
        purgeExpiredRevocations(now);

        TokenClaims claims;
        try {
            claims = codec.decodeAndVerify(request.token());
        } catch (TokenException e) {
            audit.failure("token.revoke", null, null, "unparsable token: " + e.getReason());
            return new RevokeResponse(false, "token could not be parsed: " + e.getReason());
        }

        if (TokenKind.ACCESS.equals(claims.getTyp())) {
            if (!revocations.existsByTokenTypeAndTokenRef(RevocationEntity.TYPE_ACCESS, claims.getJti())) {
                revocations.save(new RevocationEntity(RevocationEntity.TYPE_ACCESS,
                        claims.getJti(), claims.getExp(), now));
            }
            audit.success("token.revoke", claims.getClientId(), claims.getSub(), "access jti=" + claims.getJti());
            return new RevokeResponse(true, "access token revoked");
        }

        if (TokenKind.REFRESH.equals(claims.getTyp())) {
            String refreshId = claims.getRefreshId();
            Optional<RefreshTokenEntity> record = refreshTokens.findById(refreshId);
            record.ifPresent(entity -> {
                entity.setRevoked(true);
                refreshTokens.save(entity);
            });
            if (!revocations.existsByTokenTypeAndTokenRef(RevocationEntity.TYPE_REFRESH, refreshId)) {
                revocations.save(new RevocationEntity(RevocationEntity.TYPE_REFRESH,
                        refreshId, claims.getExp(), now));
            }
            audit.success("token.revoke", claims.getClientId(), claims.getSub(), "refresh id=" + refreshId);
            return new RevokeResponse(true, "refresh token revoked");
        }

        return new RevokeResponse(false, "unknown token type: " + claims.getTyp());
    }

    @Transactional(readOnly = true)
    public IntrospectResponse introspect(String token) {
        if (isBlank(token)) {
            throw OAuthException.badRequest("invalid_request", "token is required");
        }

        TokenClaims claims;
        try {
            claims = codec.decodeAndVerify(token);
        } catch (TokenException e) {
            return IntrospectResponse.inactive(e.getReason().name().toLowerCase());
        }

        long now = time.nowEpochSeconds();
        try {
            validator.validateIssuer(claims, props.getIssuer());
            validator.validateLifetime(claims, now, props.getClockSkewSec());
        } catch (TokenException e) {
            return IntrospectResponse.inactive(e.getReason().name().toLowerCase());
        }

        if (isRevoked(claims)) {
            return IntrospectResponse.inactive("revoked");
        }

        return new IntrospectResponse(true, claims.getTyp(), claims.getIss(), claims.getAud(),
                claims.getSub(), claims.getClientId(), claims.getScopes(), claims.getRoles(),
                claims.getIat(), claims.getExp(), claims.getJti(), null);
    }

    private boolean isRevoked(TokenClaims claims) {
        if (TokenKind.REFRESH.equals(claims.getTyp())) {
            String refreshId = claims.getRefreshId();
            if (refreshId == null) {
                return true;
            }
            if (revocations.existsByTokenTypeAndTokenRef(RevocationEntity.TYPE_REFRESH, refreshId)) {
                return true;
            }
            return refreshTokens.findById(refreshId)
                    .map(record -> record.isRevoked() || record.isRotated())
                    .orElse(true);
        }
        return claims.getJti() != null
                && revocations.existsByTokenTypeAndTokenRef(RevocationEntity.TYPE_ACCESS, claims.getJti());
    }

    private ClientEntity authenticateClient(String clientId, String clientSecret) {
        if (isBlank(clientId) || isBlank(clientSecret)) {
            throw OAuthException.badRequest("invalid_request", "client_id and client_secret are required");
        }
        ClientEntity client = clients.findById(clientId).orElse(null);
        if (client == null || !passwords.matches(clientSecret, client.getClientSecretHash())) {
            audit.failure("client.authenticate", clientId, null, "invalid client credentials");
            throw OAuthException.unauthorized("invalid_client", "invalid client_id or client_secret");
        }
        if (!client.isEnabled()) {
            throw OAuthException.forbidden("access_denied", "client is disabled");
        }
        return client;
    }

    private void requireGrant(ClientEntity client, String grantType) {
        if (!client.getAllowedGrants().contains(grantType)) {
            audit.failure("client.grant", client.getClientId(), null, "grant not allowed: " + grantType);
            throw OAuthException.forbidden("unauthorized_client",
                    "client is not allowed to use the " + grantType + " grant");
        }
    }

    private TokenClaims accessClaims(ClientEntity client, String subject, List<String> scopes,
                                     List<String> roles, long now) {
        TokenClaims claims = new TokenClaims();
        claims.setTyp(TokenKind.ACCESS);
        claims.setIss(props.getIssuer());
        claims.setAud(client.getAudience());
        claims.setSub(subject);
        claims.setClientId(client.getClientId());
        claims.setScopes(scopes);
        claims.setRoles(roles);
        claims.setIat(now);
        claims.setExp(now + props.getAccessTtlSec());
        claims.setJti(UUID.randomUUID().toString());
        return claims;
    }

    private IssuedRefresh issueRefreshToken(ClientEntity client, String userId, List<String> scopes, long now) {
        String refreshId = UUID.randomUUID().toString();
        long expiresAt = now + props.refreshTtlSeconds();

        TokenClaims claims = new TokenClaims();
        claims.setTyp(TokenKind.REFRESH);
        claims.setIss(props.getIssuer());
        claims.setAud(props.getIssuer());
        claims.setSub(userId);
        claims.setClientId(client.getClientId());
        claims.setScopes(scopes);
        claims.setIat(now);
        claims.setExp(expiresAt);
        claims.setJti(UUID.randomUUID().toString());
        claims.setRefreshId(refreshId);

        refreshTokens.save(new RefreshTokenEntity(refreshId, userId, client.getClientId(),
                ScopeResolver.asString(scopes), now, expiresAt));

        return new IssuedRefresh(codec.encode(claims), refreshId);
    }

    private record IssuedRefresh(String token, String refreshId) {
    }

    private TokenClaims decodeRefreshToken(String refreshToken, String clientId, long now) {
        TokenClaims claims;
        try {
            claims = codec.decodeAndVerify(refreshToken);
            validator.validate(claims, TokenKind.REFRESH, props.getIssuer(), props.getIssuer(),
                    now, props.getClockSkewSec());
        } catch (TokenException e) {
            audit.failure("token.refresh", clientId, null, "invalid refresh token: " + e.getReason());
            throw OAuthException.unauthorized("invalid_grant", "refresh token is invalid: " + e.getMessage());
        }
        if (claims.getRefreshId() == null) {
            throw OAuthException.unauthorized("invalid_grant", "refresh token has no refresh_id");
        }
        return claims;
    }

    private void purgeExpiredRevocations(long now) {
        try {
            revocations.deleteByExpiresAtLessThan(now);
        } catch (RuntimeException e) {
            log.warn("could not purge expired revocation rows", e);
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
