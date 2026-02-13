# syntax=docker/dockerfile:1

########################
# 构建阶段（按目标架构编译）
########################
FROM golang:1.21-alpine AS builder
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates git

# 依赖缓存（更快）
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# 复制源码
COPY . .

# 编译缓存（更快）
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" \
    -o /out/vmqfox-backend ./cmd/server/main.go


########################
# 运行阶段（小镜像 + 非 root）
########################
FROM alpine:3.20
WORKDIR /app

# 运行依赖 + 目录结构
RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates \
    && addgroup -S app && adduser -S -G app app \
    && mkdir -p /app/logs \
    && chown -R app:app /app

COPY --from=builder /out/vmqfox-backend /app/vmqfox-backend

# 更推荐：把示例配置放成 example，真正的 config.yaml 用挂载
# （如果你就是想镜像内直接跑，也可以再额外 COPY 成 /app/config.yaml）
COPY config.example.yaml /app/config.example.yaml

USER app

EXPOSE 8000

# 如果你的程序默认读取 /app/config.yaml，你就挂载它到这里：
# docker run -v $(pwd)/config.yaml:/app/config.yaml ...
CMD ["/app/vmqfox-backend"]
