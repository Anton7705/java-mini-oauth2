package ru.yandex.practicum.oauth0.common.codec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {
    }

    public static String encode(byte[] bytes) {
        return ENCODER.encodeToString(bytes);
    }

    public static String encode(String text) {
        return encode(text.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decode(String text) {
        return DECODER.decode(text);
    }

    public static String decodeToString(String text) {
        return new String(decode(text), StandardCharsets.UTF_8);
    }
}
