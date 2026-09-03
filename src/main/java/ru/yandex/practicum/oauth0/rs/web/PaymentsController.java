package ru.yandex.practicum.oauth0.rs.web;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.yandex.practicum.oauth0.common.api.ErrorResponse;
import ru.yandex.practicum.oauth0.rs.security.RequiresAuthority;
import ru.yandex.practicum.oauth0.rs.security.TokenPrincipal;
import ru.yandex.practicum.oauth0.rs.web.dto.CreatePaymentRequest;
import ru.yandex.practicum.oauth0.rs.web.dto.Payment;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
@RequestMapping("/api/payments")
public class PaymentsController {

    private static final Logger log = LoggerFactory.getLogger(PaymentsController.class);

    private final List<Payment> payments = new CopyOnWriteArrayList<>(List.of(
            new Payment("pay-1", "u-100", 149900, "RUB", "annual subscription"),
            new Payment("pay-2", "u-200", 25000, "RUB", "support plan")));

    @GetMapping
    @RequiresAuthority(scopes = "payments:read")
    public List<Payment> list(HttpServletRequest request) {
        TokenPrincipal principal = principal(request);
        log.info("sub={} client={} listed payments", principal.subject(), principal.clientId());
        return new ArrayList<>(payments);
    }

    @PostMapping
    @RequiresAuthority(scopes = "payments:write")
    public ResponseEntity<?> create(@RequestBody CreatePaymentRequest request, HttpServletRequest http) {
        if (request.amountMinor() == null || request.amountMinor() <= 0) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("invalid_request", "amount_minor must be a positive number"));
        }
        TokenPrincipal principal = principal(http);
        Payment payment = new Payment(
                "pay-" + UUID.randomUUID(),
                principal.subject(),
                request.amountMinor(),
                request.currency() == null ? "RUB" : request.currency(),
                request.description());
        payments.add(payment);
        log.info("sub={} client={} created payment {}", principal.subject(), principal.clientId(), payment.id());
        return ResponseEntity.status(HttpStatus.CREATED).body(payment);
    }

    @DeleteMapping("/{id}")
    @RequiresAuthority(scopes = "payments:write", roles = {"admin"})
    public ResponseEntity<?> delete(@PathVariable String id, HttpServletRequest http) {
        boolean removed = payments.removeIf(payment -> payment.id().equals(id));
        if (!removed) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("not_found", "payment " + id + " does not exist"));
        }
        log.info("sub={} deleted payment {}", principal(http).subject(), id);
        return ResponseEntity.ok(Map.of("deleted", id));
    }

    private TokenPrincipal principal(HttpServletRequest request) {
        return (TokenPrincipal) request.getAttribute(TokenPrincipal.ATTRIBUTE);
    }
}
