package com.frog.common.integration.dubbo;

import lombok.RequiredArgsConstructor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@RequiredArgsConstructor
public class InternalTokenSigner {

    public record VerifyResult(boolean ok, String callerService, String userId, long expiresAt, String reason) {}

    private final InternalTokenProperties properties;

    public String sign(String callerService, String userId) {
        long exp = Instant.now().getEpochSecond() + properties.getTtlSeconds();
        String payload = callerService + "|" + (userId == null ? "" : userId) + "|" + exp;
        String sig = hmacHex(payload);
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString((payload + "|" + sig).getBytes(StandardCharsets.UTF_8));
    }

    public VerifyResult verify(String token, String expectedCaller) {
        try {
            String raw = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
            String[] parts = raw.split("\\|");
            if (parts.length != 4) return new VerifyResult(false, null, null, 0, "MALFORMED");
            String caller = parts[0];
            String userId = parts[1];
            long exp = Long.parseLong(parts[2]);
            String sig = parts[3];
            String payload = caller + "|" + userId + "|" + exp;
            String expected = hmacHex(payload);
            if (!MessageDigest.isEqual(sig.getBytes(StandardCharsets.UTF_8),
                                       expected.getBytes(StandardCharsets.UTF_8)))
                return new VerifyResult(false, null, null, 0, "INVALID");
            if (Instant.now().getEpochSecond() > exp)
                return new VerifyResult(false, caller, userId, exp, "EXPIRED");
            if (expectedCaller != null && !expectedCaller.equals(caller))
                return new VerifyResult(false, caller, userId, exp, "CALLER_MISMATCH");
            return new VerifyResult(true, caller, userId, exp, "OK");
        } catch (Exception e) {
            return new VerifyResult(false, null, null, 0, "DECODE_FAILED: " + e.getMessage());
        }
    }

    private String hmacHex(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(properties.getSharedSecret().getBytes(StandardCharsets.UTF_8),
                                       "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
