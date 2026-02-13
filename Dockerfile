# syntax=docker/dockerfile:1

########################
# Builder (multi-arch)
########################
FROM golang:1.25-alpine AS builder
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH

# 基础依赖
RUN apk add --no-cache ca-certificates git

# 依赖缓存（go mod）
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# 复制源码
COPY . .

# 构建缓存（go build）
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" \
    -o /out/vmqfox-backend ./cmd/server/main.go

########################
# Runtime (small + non-root)
########################
FROM alpine:3.20
WORKDIR /app

# 运行依赖 + 用户 + 目录
RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates \
    && addgroup -S app && adduser -S -G app app \
    && mkdir -p /app/logs \
    && chown -R app:app /app

# 拷贝可执行文件
COPY --from=builder /out/vmqfox-backend /app/vmqfox-backend

# 保留示例配置（生产环境建议用 volume 挂载 /app/config.yaml）
# 如果仓库里没有这个文件，可以删掉这一行
COPY config.example.yaml /app/config.example.yaml

USER app

EXPOSE 8000

CMD ["/app/vmqfox-backend"]
