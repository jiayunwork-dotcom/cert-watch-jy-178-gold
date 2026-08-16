# cert-watch —— 证书到期监控与状态判定 CLI
# 遵循《Go 项目打包规范》：基于官方 golang:<go.mod 版本>-alpine 多架构镜像、保留完整工具链，
# 单阶段构建（禁止多阶段 alpine 只留二进制；评测需在容器内改代码/编译/测试）。
FROM golang:1.21-alpine

# 钉死工具链，禁止轨迹中途联网换版
ENV GOTOOLCHAIN=local
ENV CGO_ENABLED=0

WORKDIR /src

# 先复制依赖清单并下载（纯标准库项目此处为空操作，保留以契合规范）
COPY go.mod ./
RUN go mod download

# 复制全部源码并预编译，把编译缓存留在镜像里（不影响源码，模型仍可自由修改）
COPY . .
RUN go build ./...

# 进入 shell，便于评测时改代码、重编译、跑测试
CMD ["/bin/sh"]

# 常用运行方式（在宿主机改、容器里跑）：
#   docker build -t cert-watch .
#   docker run --rm -v "$PWD":/src cert-watch go run . -in /src/example/
