# NDP-Server
> 隶属于NDP的服务端程序，主要使用Python进行编写，作用为让No-Danger-Players插件/模组连接，真正的实现封禁管理功能。
>
> [NDP项目Github页](https://github.com/No-Danger-Player-Project/)



# NDP 封禁系统文档
## 数据目录在C:/NDP-Data
## config.json
```json
{
    "SECRET_VERIFICATION": "token", //用于POST请求的密钥
    "ADMIN_PORT": 5020, //服务端口
    "ADMIN_USERS": {
        "admin": "password" // 审核网页用户密码,默认为password(此处会在程序启动后自动转化为哈希值)
    }
}
```

## API

### 1. 添加/移除封禁 

`POST /add_ban`

请求数据:

```json
{
  "verification": "string", // 必填，验证密钥
  "action": "string", // 必填，操作类型(ban/remove)
  "username": "string", // 必填，用户名(不区分大小写)
  "ip": "string", // 必填，IP地址(支持带端口)
  "cause": "string" // 必填，封禁原因
}
```

响应示例: 

1. 成功封禁
```json
{
  "action": "ban",
  "username": "testUser",
  "ip": "192.168.1.1",
  "cause": "使用外挂",
  "timestamp": "2024-02-20T15:30:45.123456",
  "info": {
    "ip_related": 3,
    "total_bans": 42
  }
}
```

2. 成功解禁
```json
{
  "action": "pardon",
  "removed": ["testUser"],
  "timestamp": "2024-02-20T15:32:10.987654",
  "info": {
    "removed_players": 1,
    "affected_ips": 0
  }
}
```

### 2.封禁状态检查

`GET /check_ban`

请求数据:

```json
{
  "username": "string", // 用户名 (可选)
  "ip": "string", // IP地址 (可选)
}
```

响应示例:

1. 对于IP
```json
// 发现IP封禁
{
  "action": "kick",
  "cause": "关联封禁：testUser",
  "info": {
    "related_players": ["testUser", "hacker123"],
    "ban_type": "ip"
  }
}
```

2. 对于玩家
```json
// 发现玩家封禁
{
  "action": "kick",
  "cause": "使用外挂",
  "ip": "192.168.1.1",
  "info": {
    "related_ips": ["192.168.1.1"],
    "ban_type": "player"
  }
}
```

3. 对于未被封禁的玩家/IP
```json
// 无封禁记录
{
  "action": "allowed",
  "status": "clean",
  "timestamp": "2024-02-20T15:35:20.000000"
}
```

### 3. 获取封禁统计

`GET /bans`

响应示例:

```json
{
  "action": "list",
  "ip_count": 15,
  "player_count": 42,
  "recent_actions": [
    {
      "type": "ban",
      "username": "cheater99",
      "ip": "10.0.0.5",
      "cause": "恶意破坏",
      "timestamp": "2024-02-20T15:30:00"
    },
    {
      "type": "ban",
      "username": "spammer",
      "ip": "192.168.1.2",
      "cause": "刷屏广告",
      "timestamp": "2024-02-20T15:25:00"
    }
  ]
}
```

## 错误码
-**400**: `请求参数错误`
-**403**: `验证密钥无效`
-**404**: `未找到对应记录`
-**500**: `服务器内部错误`

## POST 请求时的安全验证

所有 POST 请求均需要添加 `verification` 参数数据代表密钥以验证:

```json
{
  "verification": "token"
}
```
