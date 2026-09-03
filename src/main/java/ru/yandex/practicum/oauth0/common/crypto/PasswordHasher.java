package ru.yandex.practicum.oauth0.common.crypto;

import org.mindrot.jbcrypt.BCrypt;

public class PasswordHasher {

    private final int logRounds;

    public PasswordHasher() {
        this(12);
    }

    public PasswordHasher(int logRounds) {
        this.logRounds = logRounds;
    }

    public String hash(String plainPassword) {
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt(logRounds));
    }

    public boolean matches(String plainPassword, String storedHash) {
        if (plainPassword == null || storedHash == null || storedHash.isBlank()) {
            return false;
        }
        try {
            return BCrypt.checkpw(plainPassword, storedHash);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
