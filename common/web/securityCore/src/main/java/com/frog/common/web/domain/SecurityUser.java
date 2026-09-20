package com.frog.common.web.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 自定义 UserDetails
 *
 * @author Deng
 * createData 2025/10/14 14:52
 * @version 1.0
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecurityUser implements UserDetails {
    private UUID userId;
    private String username;
    @com.fasterxml.jackson.annotation.JsonIgnore
    private String password;
    private String realName;
    private UUID deptId;
    /**
     * 租户 ID — Phase 1.5。
     *
     * <p>对于尚未迁移到多租户的用户,可能为 {@code null}(保留向后兼容)。
     * 由 {@code SysUserServiceImpl.getUserByUsername()} 从
     * {@code sys_user.tenant_id} 填充。
     */
    private UUID tenantId;
    /**
     * 应用 ID — Phase 1.5。
     *
     * <p>当前登录的应用(多应用场景下区分授权范围)。Phase 1.5 默认使用
     * 租户下的 {@code appCode='default'} 应用;完整 OAuth2 client_id →
     * app_id 的映射留待后续阶段。
     */
    private UUID appId;
    private Integer status;
    private Integer accountType;
    private Integer userLevel;
    private Integer dataScope;
    @Builder.Default
    private Set<String> roles = Collections.emptySet();
    @Builder.Default
    private Set<String> permissions = Collections.emptySet();
    @com.fasterxml.jackson.annotation.JsonIgnore
    private String twoFactorSecret;

    // Session / device / auth-method context
    private String deviceId;
    private String ipAddress;
    @Builder.Default
    private List<String> amr = Collections.emptyList();

    // 安全相关字段
    private Boolean twoFactorEnabled;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonDeserialize(using = LocalDateTimeDeserializer.class)
    @JsonSerialize(using = LocalDateTimeSerializer.class)
    private LocalDateTime passwordExpireTime;
    private Boolean forceChangePassword;
    
    @JsonIgnore
    private transient Collection<? extends GrantedAuthority> authorities;

    @Override
    @JsonIgnore
    public @NonNull Collection<? extends GrantedAuthority> getAuthorities() {
        if (authorities != null) {
            return authorities;
        }
        // 合并角色和权限，防御空集合
        Set<GrantedAuthority> result = (roles != null ? roles : Collections.<String>emptySet()).stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        result.addAll((permissions != null ? permissions : Collections.<String>emptySet()).stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet()));
        this.authorities = Collections.unmodifiableSet(result);
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public @NonNull String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.status != 2; // 2表示锁定
    }

    @Override
    public boolean isCredentialsNonExpired() {
        if (passwordExpireTime == null) {
            return true;
        }
        return passwordExpireTime.isAfter(LocalDateTime.now());
    }

    @Override
    public boolean isEnabled() {
        return this.status == 1; // 1表示启用
    }
}
