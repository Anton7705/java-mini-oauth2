package ru.yandex.practicum.oauth0.common.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ru.yandex.practicum.oauth0.common.codec.Base64Url;
import ru.yandex.practicum.oauth0.common.crypto.HmacSigner;

import java.util.Map;

public class TokenCodec {

    private static final String HEADER_JSON = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

    private final HmacSigner signer;
    private final ObjectMapper mapper;

    public TokenCodec(HmacSigner signer, ObjectMapper mapper) {
        this.signer = signer;
        this.mapper = mapper;
    }

    public String encode(TokenClaims claims) {
        try {
            String header = Base64Url.encode(HEADER_JSON);
            String payload = Base64Url.encode(mapper.writeValueAsString(claims));
            String signingInput = header + "." + payload;
            return signingInput + "." + signer.sign(signingInput);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("unable to serialize token claims", e);
        }
    }

    public TokenClaims decodeAndVerify(String token) {
        if (token == null || token.isBlank()) {
            throw new TokenException(TokenException.Reason.MALFORMED, "token is empty");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new TokenException(TokenException.Reason.MALFORMED,
                    "expected 3 dot-separated parts, got " + parts.length);
        }

        String headerJson;
        String payloadJson;
        try {
            headerJson = Base64Url.decodeToString(parts[0]);
            payloadJson = Base64Url.decodeToString(parts[1]);
        } catch (IllegalArgumentException e) {
            throw new TokenException(TokenException.Reason.MALFORMED, "token is not valid Base64URL");
        }

        assertSupportedAlgorithm(headerJson);

        if (!signer.verify(parts[0] + "." + parts[1], parts[2])) {
            throw new TokenException(TokenException.Reason.BAD_SIGNATURE);
        }

        try {
            TokenClaims claims = mapper.readValue(payloadJson, TokenClaims.class);
            if (claims.getTyp() == null || claims.getExp() == null || claims.getIat() == null) {
                throw new TokenException(TokenException.Reason.MISSING_CLAIM,
                        "typ, iat and exp are required");
            }
            return claims;
        } catch (JsonProcessingException e) {
            throw new TokenException(TokenException.Reason.MALFORMED, "payload is not valid JSON");
        }
    }

    private void assertSupportedAlgorithm(String headerJson) {
        Object alg;
        try {
            Map<?, ?> header = mapper.readValue(headerJson, Map.class);
            alg = header.get("alg");
        } catch (JsonProcessingException e) {
            throw new TokenException(TokenException.Reason.MALFORMED, "header is not valid JSON");
        }
        if (!HmacSigner.ALGORITHM.equals(alg)) {
            throw new TokenException(TokenException.Reason.UNSUPPORTED_ALGORITHM,
                    "only " + HmacSigner.ALGORITHM + " is supported, got " + alg);
        }
    }
}
