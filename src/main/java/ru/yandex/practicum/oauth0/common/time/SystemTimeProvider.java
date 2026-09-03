package ru.yandex.practicum.oauth0.common.time;

import java.time.Clock;

public class SystemTimeProvider implements TimeProvider {

    private final Clock clock;

    public SystemTimeProvider() {
        this(Clock.systemUTC());
    }

    public SystemTimeProvider(Clock clock) {
        this.clock = clock;
    }

    @Override
    public long nowEpochSeconds() {
        return clock.instant().getEpochSecond();
    }
}
