package com.frog.common.integration.dubbo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.common.constants.CommonConstants;
import org.apache.dubbo.common.extension.Activate;
import org.apache.dubbo.rpc.Filter;
import org.apache.dubbo.rpc.Invocation;
import org.apache.dubbo.rpc.Invoker;
import org.apache.dubbo.rpc.Result;
import org.apache.dubbo.rpc.RpcException;
import org.apache.dubbo.rpc.RpcInvocation;

@Slf4j
@RequiredArgsConstructor
@Activate(group = {CommonConstants.PROVIDER, CommonConstants.CONSUMER})
public class InternalTokenFilter implements Filter {

    private final InternalTokenSigner signer;
    private final InternalTokenProperties properties;
    private final String expectedCaller;

    public InternalTokenFilter(InternalTokenSigner signer, InternalTokenProperties properties) {
        this(signer, properties, null);
    }

    @Override
    public Result invoke(Invoker<?> invoker, Invocation invocation) throws RpcException {
        if (!properties.isEnabled()) return invoker.invoke(invocation);
        RpcInvocation rpcInv = (RpcInvocation) invocation;
        if (rpcInv.getInvoker() == null || isProvider(rpcInv)) {
            return invokeProvider(invoker, rpcInv);
        }
        return invokeConsumer(invoker, rpcInv);
    }

    private boolean isProvider(RpcInvocation inv) {
        return inv.getInvoker() != null;
    }

    private Result invokeProvider(Invoker<?> invoker, RpcInvocation rpcInv) {
        String token = rpcInv.getAttachment("internal-token");
        InternalTokenSigner.VerifyResult r = signer.verify(token, expectedCaller);
        if (!r.ok()) {
            log.warn("Dubbo internal-token rejected caller={} reason={}",
                     r.callerService(), r.reason());
            throw new RpcException(RpcException.FORBIDDEN_EXCEPTION,
                    "internal-token rejected: " + r.reason());
        }
        CallerContext.set(r.userId(), r.callerService());
        try {
            return invoker.invoke(rpcInv);
        } finally {
            CallerContext.clear();
        }
    }

    private Result invokeConsumer(Invoker<?> invoker, RpcInvocation rpcInv) {
        String caller = expectedCaller != null ? expectedCaller : "unknown";
        String userId = CallerContext.getUserId();
        String token = signer.sign(caller, userId);
        rpcInv.setAttachment("internal-token", token);
        return invoker.invoke(rpcInv);
    }
}
