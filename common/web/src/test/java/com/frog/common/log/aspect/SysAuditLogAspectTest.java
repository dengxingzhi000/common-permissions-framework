package com.frog.common.log.aspect;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.frog.common.data.audit.SysAuditLogMapper;
import com.frog.common.data.audit.SysAuditLogPO;
import com.frog.common.log.annotation.AuditLog;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SysAuditLogAspectTest {

    @Mock
    SysAuditLogMapper mapper;

    @InjectMocks
    SysAuditLogAspect aspect;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private AuditLog annotatedAnnotation() throws NoSuchMethodException {
        Method m = SampleTarget.class.getDeclaredMethod("doIt");
        return m.getAnnotation(AuditLog.class);
    }

    @Test
    void around_writesAuditLogRowWithAnnotationFields() throws Throwable {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/system/users");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("User-Agent", "JUnit");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ProceedingJoinPoint pjp = mock(ProceedingJoinPoint.class);
        MethodSignature sig = mock(MethodSignature.class);
        when(pjp.getSignature()).thenReturn(sig);
        when(sig.getMethod()).thenReturn(SampleTarget.class.getDeclaredMethod("doIt"));
        when(pjp.getArgs()).thenReturn(new Object[]{});
        when(pjp.proceed()).thenReturn("ok");

        aspect.setObjectMapper(objectMapper);
        Object result = aspect.around(pjp);
        assertThat(result).isEqualTo("ok");

        ArgumentCaptor<SysAuditLogPO> captor = ArgumentCaptor.forClass(SysAuditLogPO.class);
        verify(mapper).insert(captor.capture());
        SysAuditLogPO po = captor.getValue();
        assertThat(po.getRequestMethod()).isEqualTo("GET");
        assertThat(po.getRequestUri()).isEqualTo("/api/system/users");
        assertThat(po.getStatus()).isEqualTo(1);
        assertThat(po.getExecuteTime()).isNotNull();

        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void around_failure_marksStatusZeroAndThrows() throws Throwable {
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(new MockHttpServletRequest("POST", "/api/x")));

        ProceedingJoinPoint pjp = mock(ProceedingJoinPoint.class);
        MethodSignature sig = mock(MethodSignature.class);
        when(pjp.getSignature()).thenReturn(sig);
        when(sig.getMethod()).thenReturn(SampleTarget.class.getDeclaredMethod("doIt"));
        when(pjp.getArgs()).thenReturn(new Object[]{});
        RuntimeException boom = new RuntimeException("kaboom");
        when(pjp.proceed()).thenThrow(boom);

        aspect.setObjectMapper(objectMapper);

        try {
            aspect.around(pjp);
        } catch (RuntimeException expected) {
            assertThat(expected).isSameAs(boom);
        }

        ArgumentCaptor<SysAuditLogPO> captor = ArgumentCaptor.forClass(SysAuditLogPO.class);
        verify(mapper).insert(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo(0);
        assertThat(captor.getValue().getErrorMsg()).isEqualTo("kaboom");

        RequestContextHolder.resetRequestAttributes();
    }

    static class SampleTarget {
        @AuditLog(operation = "查询用户", businessType = "QUERY", riskLevel = 2)
        public String doIt() {
            return "ok";
        }
    }
}
