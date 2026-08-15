# task022-merkle

基于 SHA-256 的 Merkle 树构建与校验服务（仅标准库，无第三方依赖）。

## 功能

- `POST /root`：接收数据块列表，返回 Merkle 根哈希与叶子数量。
- `POST /proof`：接收数据块列表与索引，返回该数据块的包含性证明（叶子哈希、从叶子到根的兄弟哈希序列、根哈希）。
- `POST /verify`：接收叶子哈希、证明序列与根哈希，返回证明是否成立。
- `GET /healthz`：健康检查。

## 哈希约定

- 叶子哈希 = SHA-256(数据块 UTF-8 字节)（小写十六进制）。
- 内部节点哈希 = SHA-256(左子原始字节 || 右子原始字节)。
- 构建时每层节点数为奇数且大于 1 时，复制末尾节点与自身配对；单节点层即为根，因此单数据块树的根等于该数据块的叶子哈希。

## 运行

```bash
go run . server --addr :8080   # 启动服务
go run . --smoke-test          # 自检
```

## 构建

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o task022-merkle .
docker buildx build --platform linux/amd64 --load -t task022-merkle:amd64 .
docker buildx build --platform linux/arm64 --load -t task022-merkle:arm64 .
```
