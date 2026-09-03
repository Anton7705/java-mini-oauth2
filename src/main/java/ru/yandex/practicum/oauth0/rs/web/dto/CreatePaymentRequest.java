package ru.yandex.practicum.oauth0.rs.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record CreatePaymentRequest(
        @JsonProperty("amount_minor") Long amountMinor,
        String currency,
        String description) {
}
