package com.frog.common.security.identity;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdentityTokenPayloadTest {

    @Test
    void serialize_deserialize_roundTrip() {
        IdentityTokenPayload p = new IdentityTokenPayload(
                UUID.randomUUID(), "alice", "dev-1",
                List.of("user.read"), Instant.now().getEpochSecond(), UUID.randomUUID().toString());
        String wire = IdentityTokenPayloadCodec.encode(p);
        IdentityTokenPayload decoded = IdentityTokenPayloadCodec.decode(wire);
        assertThat(decoded.userId()).isEqualTo(p.userId());
        assertThat(decoded.authorities()).containsExactly("user.read");
    }

    @Test
    void decode_invalidBase64_throws() {
        assertThatThrownBy(() -> IdentityTokenPayloadCodec.decode("!!!not-base64!!!"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}