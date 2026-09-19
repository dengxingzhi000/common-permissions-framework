package com.frog.common.integration.dubbo;

import org.apache.dubbo.rpc.Invocation;
import org.apache.dubbo.rpc.Result;
import org.apache.dubbo.rpc.RpcException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class InternalTokenFilterTest {

    private InternalTokenFilter filter;
    private InternalTokenSigner signer;

    @BeforeEach
    void setup() {
        InternalTokenProperties props = new InternalTokenProperties();
        props.setEnabled(true);
        props.setSharedSecret("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        props.setTtlSeconds(60);
        signer = new InternalTokenSigner(props);
        filter = new InternalTokenFilter(signer, props, "auth-service");
    }

    @Test
    void serverSide_validToken_passes() {
        String token = signer.sign("auth-service", "u1");
        org.apache.dubbo.rpc.Invoker<?> invoker = mock(org.apache.dubbo.rpc.Invoker.class);
        Invocation inv = mock(Invocation.class);
        org.apache.dubbo.rpc.RpcInvocation rpcInv = new org.apache.dubbo.rpc.RpcInvocation();
        rpcInv.setAttachment("internal-token", token);
        when(invoker.invoke(ArgumentMatchers.any(Invocation.class))).thenReturn(mock(Result.class));

        Result r = filter.invoke(invoker, rpcInv);
        org.assertj.core.api.Assertions.assertThat(r).isNotNull();
    }

    @Test
    void serverSide_missingToken_throws() {
        org.apache.dubbo.rpc.Invoker<?> invoker = mock(org.apache.dubbo.rpc.Invoker.class);
        org.apache.dubbo.rpc.RpcInvocation rpcInv = new org.apache.dubbo.rpc.RpcInvocation();

        assertThatThrownBy(() -> filter.invoke(invoker, rpcInv))
                .isInstanceOf(RpcException.class);
    }
}
