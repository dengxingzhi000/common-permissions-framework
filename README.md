<div align="center">

# CommonPermissionsFramework

### 企业级微服务权限框架 —— 开箱即用的认证、授权与多租户隔离。

**Spring Boot 4 + Spring Security 7 + OAuth2 + JWT + WebAuthn，
RBAC、数据权限、网关安全与决策 API 全部内置。**

[![Build](https://img.shields.io/github/actions/workflow/status/dengxingzhi000/common-permissions-framework/ci.yaml?branch=master&style=flat-square&logo=github&label=ci)](https://github.com/dengxingzhi000/common-permissions-framework/actions)
[![Stars](https://img.shields.io/github/stars/dengxingzhi000/common-permissions-framework?color=ffcb47&labelColor=black&style=flat-square&logo=github)](https://github.com/dengxingzhi000/common-permissions-framework/stargazers)
[![Forks](https://img.shields.io/github/forks/dengxingzhi000/common-permissions-framework?color=8ae8ff&labelColor=black&style=flat-square&logo=github)](https://github.com/dengxingzhi000/common-permissions-framework/network/members)
[![Release](https://img.shields.io/github/v/release/dengxingzhi000/common-permissions-framework?labelColor=black&style=flat-square)](https://github.com/dengxingzhi000/common-permissions-framework/releases/tag/v1.5.0)
[![Java](https://img.shields.io/badge/Java-21-007396?logo=openjdk&logoColor=white&style=flat-square)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.1.1-6DB33F?logo=springboot&logoColor=white&style=flat-square)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](./LICENSE)

[快速开始](#快速开始) · [能力矩阵](#能力矩阵) · [技术栈](#技术栈) · [项目结构](#项目结构) · [FAQ](#faq) · [更新日志](#更新日志) · [贡献](#贡献指南)

<code>docker compose -f docker-compose.yaml up -d</code>

</div>

> [!IMPORTANT]
> **Compose 文件名是 `docker-compose.yaml`（不是 `.yml`）。** 另外网关端口取决于启动
> 方式：`docker compose` 启动时为 **9095**（compose 通过 `SERVER_PORT` 覆盖），
> 而用 `mvn spring-boot:run` 走默认 profile 时为 **8761**。README 旧版本里的
> `REDIS_PORT=63379` 只适用于手工 `docker run -p 63379:6379` 的场景，
> compose 中 Redis 映射的是 `6379`。

---

权限系统最难的不是写一个 `@PreAuthorize`，而是在多服务、多租户、跨进程的
前提下，让每一次鉴权都可追溯、可撤销、可解释。这个框架把这些做成了默认行为。

CommonPermissionsFramework 整合 Spring Security 7、Spring Authorization Server、
JWT、WebAuthn、Nacos 与 Dubbo，提供一套可直接落地的权限底座：用户/角色/部门/
权限/审计的完整模块，多租户隔离（`sys_tenant` + `sys_application` + 字段级
`tenant_id`），以及带 deny-overrides 语义的决策 API。

架构上它按 `system` / `auth` / `gateway` 三个可部署服务加一组公共库组织，
数据库按领域拆分为 `db_user`、`db_org`、`db_permission`、`db_audit`、
`db_approval`、`db_notify`。

## 快速开始

### 前置依赖

- **JDK 21** 或更高版本
- **Maven 3.8+**
- **Docker & Docker Compose**（推荐路径，一键起全部依赖与服务）

### 1. 启动依赖与服务

```bash
docker compose -f docker-compose.yaml up -d
```

compose 会依次拉起 PostgreSQL、Redis、Nacos，再按依赖顺序启动
`system-service`（8081）、`auth-service`（8082）与 `gateway`（9095）。

<details>
<summary><strong>不想用 Docker？手工启动依赖</strong></summary>

```bash
docker run -d --name nacos -e MODE=standalone -p 8848:8848 nacos/nacos-server:v2.2.0
docker run -d --name redis -p 63379:6379 redis:7
docker run -d --name postgres -p 5432:5432 -e POSTGRES_DB=permissions postgres:15
```

注意这套手工路径把 Redis 映射到宿主机 **63379**，与 compose 的 `6379` 不同，
`REDIS_PORT` 需相应调整。

</details>

### 2. 启动服务（顺序重要）

```bash
# 1. system-service（基础服务，其他服务都依赖它）
cd system/service
mvn spring-boot:run

# 2. auth-service（认证服务）
cd ../../auth
mvn spring-boot:run

# 3. gateway（API 网关）
cd ../gateway
mvn spring-boot:run
```

> [!NOTE]
> **此路径下网关监听 8761**，而非 compose 中的 9095 —— 因为没有 `SERVER_PORT`
> 覆盖。想与 compose 保持一致，加 `--spring.profiles.active=local` 即可。

### 3. 验证

```bash
# 已注册服务
curl http://localhost:8848/nacos/v1/ns/service/list

# 网关健康检查（按你的启动方式二选一）
curl http://localhost:9095/actuator/health   # docker compose
curl http://localhost:8761/actuator/health   # mvn spring-boot:run

# 获取 JWT 令牌
curl -X POST http://localhost:8761/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### 环境变量

部署前必须设置以下环境变量：

```bash
# 数据库
DB_HOST=localhost
DB_PORT=5432
DB_NAME=permissions
DB_USERNAME=postgres
DB_PASSWORD=your_db_password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# JWT
JWT_SECRET=your_jwt_secret_at_least_256_bits

# Nacos
NACOS_SERVER=localhost:8848
NACOS_NAMESPACE=public
NACOS_GROUP=DEFAULT_GROUP

# 安全
API_SIGNING_SECRET=your_api_signing_secret
IDENTITY_TOKEN_SECRET=your_identity_token_secret
SENTINEL_DASHBOARD=localhost:8080
```

> [!WARNING]
> **`docker-compose.yaml` 中内置的是测试用密钥**（`JWT_SECRET` 等为 base64 占位串）。
> 它只用于本地跑通链路，任何非本机部署都必须通过环境变量或密钥管理系统替换。

### 访问入口

| 服务             | 端口   | 说明                                  |
| ---------------- | ------ | ------------------------------------- |
| `gateway`        | 9095 ⚠ | compose 启动；`mvn` 启动为 8761       |
| `auth-service`   | 8082   | 认证服务                              |
| `system-service` | 8081   | 系统服务                              |
| Nacos            | 8848   | 配置中心 + 注册中心（另开 9848 gRPC） |
| PostgreSQL       | 5432   | 主库                                  |
| Redis            | 6379   | 缓存（手工路径下为 63379）            |

## 能力矩阵

下表所列能力均由内置模块实现。右列给出的是真正约束设计的因素。

| 能力           | 框架提供什么                                                          | 关键实现与约束                                                                     |
| -------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| 身份认证       | JWT + 刷新令牌、OAuth2 统一认证中心、登出与全局吊销                   | `/v1/oauth2/logout` 与 `/v1/oauth2/logout/all`，后者需 `oauth2:logout:global` 权限 |
| 多因素认证     | WebAuthn（FIDO2）无密码登录、MFA 两步验证（TOTP）                     | WebAuthn 源站由服务端 `rpId` 校验，不信任客户端传入                                |
| 权限模型       | RBAC 角色权限、动态权限加载、资源级校验、数据权限 DataScope           | 插件化设计，可继承接口并覆盖 Bean 扩展                                             |
| 决策 API       | deny-overrides 语义的 `DecisionService`，支持单条/批量/权限清单查询   | `POST /v1/decision/check`；`sys_grant` + `sys_policy_version`                      |
| 决策审计       | 每次权限评估自动落库（subject / action / resource / effect / reason） | `DecisionRecorder`，供事后审计与策略调优                                           |
| 多租户隔离     | `sys_tenant` + `sys_application`，所有领域表带 `tenant_id`            | `TenantContextHolder` 自动注入；JWT 携带 `tenant_id` + `app_id`                    |
| 网关安全       | IP 黑/白名单（Redis 动态）、HMAC-SHA256 API 签名、mTLS                | Redis `SETNX` 防重放，避免 nonce TOCTOU 竞态                                       |
| 跨进程身份传播 | Dubbo SPI 过滤器签名内部令牌，服务间身份可信传递                      | `InternalTokenSigner`                                                              |
| 组织架构       | 用户、角色、部门三级权限体系，在线用户与会话控制                      | 账号禁用即撤销（`UserRevocationService`）                                          |
| 消息集成       | Kafka + RabbitMQ 双引擎、幂等消费、事件驱动                           | 受限信任包反序列化，修复过 Kafka 反序列化 RCE                                      |
| 数据持久化     | MyBatis-Plus + PostgreSQL、ShardingSphere 分库分表、读写分离          | `@Master` / `@Slave` 注解路由，多级缓存（本地 + Redis）                            |
| 可观测性       | Prometheus、Grafana、SkyWalking、Sentinel、ELK                        | Sentinel 熔断降级；Redis 清理用 `SCAN` 而非 `KEYS`                                 |

## 技术栈

### 核心框架

| 技术                        | 版本       | 说明            |
| --------------------------- | ---------- | --------------- |
| Java                        | 21         | 编程语言        |
| Spring Boot                 | 4.1.1      | Web 框架        |
| Spring Cloud                | 2025.1.0   | 微服务框架      |
| Spring Security             | 7.0        | 安全框架        |
| Spring Authorization Server | 1.5        | OAuth2 授权服务 |
| Spring Cloud Alibaba        | 2025.0.0.0 | 阿里云生态      |

### 中间件

| 组件             | 用途                                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------- |
| Nacos            | 配置中心 + 服务发现                                                                                     |
| Dubbo            | 高性能 RPC                                                                                              |
| OpenFeign        | HTTP 客户端（降级备用）                                                                                 |
| Redis            | 缓存 + 分布式锁 + 防重放                                                                                |
| Kafka / RabbitMQ | 消息队列                                                                                                |
| PostgreSQL       | 关系型数据库（多库：`db_user` / `db_org` / `db_permission` / `db_audit` / `db_approval` / `db_notify`） |
| Flyway           | 数据库迁移（`system/service` 模块下 `db/migration/`）                                                   |

### 可观测性

| 工具       | 功能               |
| ---------- | ------------------ |
| Prometheus | 指标收集           |
| Grafana    | 可视化监控         |
| SkyWalking | 全链路追踪         |
| Sentinel   | 流量控制、熔断降级 |
| ELK        | 日志聚合分析       |

## 项目结构

```
common-permissions-framework/
├── auth/                  # 认证服务（OAuth2 + WebAuthn + JWT）
├── gateway/               # API 网关（Spring Cloud Gateway）
├── system/                # 系统服务
│   ├── api/               # Dubbo API 接口（轻量，不依赖 service）
│   └── service/           # 服务实现 + Dubbo providers + Flyway 迁移
├── common/                # 公共模块
│   ├── core/              # 纯 Java 工具（UUIDv7、异常、PageResult，无 Spring）
│   ├── security-api/      # 安全 DTO 与接口（DTO、IdentityToken、DecisionEvent）
│   ├── sdk-api/           # 对外 SDK 接口定义
│   ├── data/              # MyBatis-Plus + 多级缓存 + DataScope + 读写分离
│   ├── web/               # Web 安全过滤器 + JWT + Feign + UAA 配置
│   │   └── securityCore/  # SecurityUser 等安全核心域对象
│   ├── monitoring/        # 监控 + Sentinel 熔断
│   └── integration/       # Kafka / RabbitMQ 消息集成
├── sdk-java/              # 供业务方集成的 Java SDK
├── eda/                   # 事件驱动架构原型
├── config/                # 配置模板
├── docs/                  # 设计文档与计划（含 docs/superpowers/）
├── charts/                # Helm Charts
├── scripts/               # 部署脚本 + 数据库初始化 SQL
├── .github/workflows/     # CI、CD、回滚、schema 校验
└── Dockerfile             # 多阶段构建（按 MODULE 参数构建单服务）
```

> [!NOTE]
> `sdk-java` 与 `common/sdk-api` 是对外集成入口，`common/sdk-api` 定义接口，
> `sdk-java` 提供完整实现。两者都在父 POM 的 `<modules>` 中，但旧版 README 的
> 项目结构图遗漏了它们。

## FAQ

<details>
<summary><strong>支持哪些数据库？</strong></summary>

主要支持 PostgreSQL 15+。MyBatis-Plus 支持的其他数据库（MySQL、Oracle 等）
理论上也可以使用，需要修改 `DbType` 配置。

</details>

<details>
<summary><strong>可以用于生产环境吗？</strong></summary>

可以。框架经过架构审查，修复了 MFA 绕过、反序列化 RCE、硬编码密钥、
WebAuthn 源站绕过等安全问题（详见 v1.4.0 更新日志）。生产部署需确保所有
敏感配置通过环境变量注入 —— `docker-compose.yaml` 内的密钥仅供本地使用。

</details>

<details>
<summary><strong>如何扩展权限系统？</strong></summary>

权限系统采用插件化设计，可以通过继承相关接口和覆盖 Bean 配置来扩展。

</details>

<details>
<summary><strong>如何禁用某些安全功能？</strong></summary>

所有安全功能都可以通过配置文件启用/禁用，详见各服务的 `application.yaml`。

</details>

<details>
<summary><strong>网关端口到底是 8761 还是 9095？</strong></summary>

取决于启动方式。`gateway/src/main/resources/application.yaml` 中为 **8761**，
`application-local.yaml` 中为 **9095**，而 `docker-compose.yaml` 通过
`SERVER_PORT=9095` 覆盖。文档 curl 示例中的 9095 属于 compose 与 local
profile 路径。

</details>

## 更新日志

### v1.5.0（2026-09-20）— 多租户基础 + Phase 0 安全加固 + OAuth2 登出重构

**Phase 1 多租户基础**

- `sys_tenant` + `sys_application` 实体；所有领域表新增 `tenant_id` 列
- `TenantContextHolder` + `TenantInterceptor` + servlet 过滤器，自动注入租户上下文
- 多租户 `RegisteredClient`（`sys_registered_client` 表，替代硬编码 `InMemoryRegisteredClientRepository`）
- JWT 携带 `tenant_id` + `app_id` 声明；网关透传 `X-Tenant-Id` + `X-App-Id`
- `SysAuditLog` 合并到 `common/security-api` + `common/data` PO（P1-6 清理）
- `sys_resource` 目录 + `sys_grant` + `sys_policy_version`
- `DecisionService`（deny-overrides 评估）+ `POST /v1/decision/check` + 批量 + 权限查询 API

**Phase 0 安全基础设施**

- `IdentityTokenVerificationFilter`（servlet + WebFlux），含 jti 防重放
- `DecisionRecorder` + 决策日志表，过滤器与权限评估自动写入
- `JwtMigrationShim` + OAuth2 AS claim 增广
- `UserRevocationService` 账号禁用即撤销
- Dubbo `InternalTokenSigner` + SPI 过滤器，跨进程身份传播

**OAuth2 登出控制器重构**

- `IOAuth2LogoutService` 服务层提取；`SideIndexingOAuth2AuthorizationService` 装饰器维护 Redis 侧索引 `oauth:user:auths:{userId}`
- 端点拆分为 `/v1/oauth2/logout`（单客户端，需 `isAuthenticated`）与 `/v1/oauth2/logout/all`（全局，需 `oauth2:logout:global` 权限）
- 新权限点 `oauth2:logout:global` 通过 Flyway 自动注册并授权给 `ROLE_SUPER_ADMIN`

**API 版本化与基础设施**

- 所有接口统一加 `/v1/` 前缀（保留旧路径向后兼容）
- Flyway 接入 `system/service` 的 `db_permission` 数据源（首次启动会顺带跑 `V20260920_03`）
- Lombok annotation processor 启用（修复 Spring Boot 4.1 的 `@Data` 不生成方法问题）
- `SysUserPermissionServiceImpl` 重复 `@CacheEvict` 改为 `@Caching` 包裹

**Bug 修复**

- `TenantSqlInterceptor` 注入租户过滤时正确包裹已有 WHERE 子句
- 单客户端登出使用 `@AuditLog(riskLevel=2)`（规范 G7 一致性）
- 多个测试修正：Mockito `any()` 重载歧义、`@Caching` 注解使用、Service 上下文加载、DecisionService 角色授权展开

> [!WARNING]
> **行为变更：** `DecisionServiceImpl.roleGrantsAction()` 中，role-target grant 的
> `effect="allow"` 现在要求该角色必须包含与请求 action 匹配的 permission
> （之前过于宽松）。`SysPermissionControllerAuthorizationTest` 因 Dubbo
> `@DubboService` 与 `@WebMvcTest` 切片冲突暂时禁用，待 Phase 1.4 跟进。

### v1.4.0（2026-06-18）— 架构审查修复

**安全修复（P0）**

- 修复 Token 刷新 MFA 绕过漏洞
- 修复 Kafka 反序列化 RCE（受限信任包）
- 移除所有硬编码密钥，改用环境变量
- 修复 WebAuthn 源站绕过（服务端 rpId）
- 修复 JWK URI 硬编码为 localhost

**可靠性修复（P1）**

- 修复 API 签名 nonce TOCTOU 竞态（Redis SETNX）
- 新增 ReadWriteRoutingCleanupFilter 防止 ThreadLocal 泄漏
- 修复 checkResourcePermission SQL 忽略参数
- SecurityUser 敏感字段添加 @JsonIgnore

**性能修复（P2）**

- BusinessMetrics 无界 Map 改为 Guava Cache（10K 上限）
- 修复 RoundRobinLoadBalancer 整数溢出
- TokenCleanupTask Redis KEYS 改为 SCAN
- GlobalExceptionHandler 从注释中恢复
- 修复 StripPrefix 双重应用

**构建修复**

- 修复 SentinelAutoConfiguration UTF-16 编码损坏
- 修复 Jackson 3.x 兼容性（Spring Kafka 4.x）
- 补全 Feign 客户端缺失方法

### v1.3.0（2025-12-16）

- 新增企业级读写分离框架
- 新增数据同步框架（Kafka + 幂等消费 + 重试）
- Spring Boot 4.0 兼容性优化

### v1.2.0（2025-12-11）

- 新增完整消息集成框架（Kafka/RabbitMQ）
- 强化 IP 访问控制和身份认证传播
- 优化数据权限控制系统

### v1.1.0（2025-10-20）

- 集成 WebAuthn 多因素认证
- 完善安全框架配置

### v1.0.0（2025-09-26）

- 首次正式发布

## Star 历程

<a href="https://www.star-history.com/?repos=dengxingzhi000%2Fcommon-permissions-framework&amp;type=date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=dengxingzhi000/common-permissions-framework&amp;type=date&amp;theme=dark&amp;legend=top-left" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=dengxingzhi000/common-permissions-framework&amp;type=date" />
    <img alt="common-permissions-framework GitHub star 历程" src="https://api.star-history.com/chart?repos=dengxingzhi000/common-permissions-framework&amp;type=date" />
  </picture>
</a>

## 贡献指南

我们欢迎任何形式的贡献！提交 PR 前请先阅读
[CONTRIBUTING.md](./CONTRIBUTING.md)。

### 提交流程

1. Fork 项目
2. 创建特性分支（`git checkout -b feature/AmazingFeature`）
3. 提交更改（`git commit -m 'feat: Add AmazingFeature'`）
4. 推送到分支（`git push origin feature/AmazingFeature`）
5. 创建 Pull Request

### 代码规范

- Java 21，遵循 [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html)
- 使用 Lombok 减少模板代码
- 所有公共方法需要 JavaDoc 注释
- 提交信息遵循[约定式提交](https://www.conventionalcommits.org/zh-hans/)

安全问题请通过 [SECURITY.md](./SECURITY.md) 反馈，行为准则见
[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)。

## 许可证

本项目采用 Apache License 2.0 许可证，详见 [LICENSE](./LICENSE)。

---

<div align="center">

**Made with ❤️ by [dengxingzhi](https://github.com/dengxingzhi000)**

如果项目对你有帮助，请给个 Star 支持一下！

</div>
