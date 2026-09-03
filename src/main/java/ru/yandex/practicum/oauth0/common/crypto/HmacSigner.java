package ru.yandex.practicum.oauth0.common.crypto;

import ru.yandex.practicum.oauth0.common.codec.Base64Url;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class HmacSigner {

    public static final String ALGORITHM = "HS256";

    private static final String JCA_ALGORITHM = "HmacSHA256";

    private final byte[] secret;

    public HmacSigner(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("signing secret must not be empty");
        }
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    public String sign(String data) {
        try {
            Mac mac = Mac.getInstance(JCA_ALGORITHM);
            mac.init(new SecretKeySpec(secret, JCA_ALGORITHM));
            return Base64Url.encode(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("unable to compute HMAC-SHA256 signature", e);
        }
    }

    public boolean verify(String data, String signature) {
        if (signature == null) {
            return false;
        }
        byte[] expected = sign(data).getBytes(StandardCharsets.UTF_8);
        byte[] provided = signature.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, provided);
    }
}
