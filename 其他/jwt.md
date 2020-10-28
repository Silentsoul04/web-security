# JWT安全

## 一、JWT定义及其组成

 JWT（JSON Web Token）是一个非常轻巧的规范。这个规范允许我们使用JWT在用户和服务器之间传递安全可靠的信息。

一个JWT实际上就是一个字符串，它由三部分组成，头部、载荷与签名。 

#### 载荷（Payload）

 我们先将用户认证的操作描述成一个JSON对象。其中添加了一些其他的信息，帮助今后收到这个JWT的服务器理解这个JWT。 

```json
{
    "sub": "1",
    "iss": "http://localhost:8000/auth/login",
    "iat": 1451888119,
    "exp": 1454516119,
    "nbf": 1451888119,
    "jti": "37c107e4609ddbcc9c096ea5ee76c667"
}
```

 这里面的前6个字段都是由JWT的标准所定义的。 

- sub: 该JWT所面向的用户
- iss: 该JWT的签发者
- iat(issued at): 在什么时候签发的token
- exp(expires): token什么时候过期
- nbf(not before)：token在此时间之前不能被接收处理
- jti：JWT ID为web token提供唯一标识

 这些定义都可以在[标准](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32)中找到。

将上面的JSON对象进行base64编码可以得到下面的字符串： 

```base64
eyJzdWIiOiIxIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWx
ob3N0OjgwMDFcL2F1dGhcL2xvZ2luIiwiaWF0IjoxNDUxODg4MTE5LCJleHAiOjE0NTQ1MTYxMTksIm5iZiI6MTQ1MTg4OD
ExOSwianRpIjoiMzdjMTA3ZTQ2MDlkZGJjYzljMDk2ZWE1ZWU3NmM2NjcifQ
```

 这个字符串我们将它称作JWT的Payload（载荷）。

如果你使用Node.js，可以用Node.js的包base64url来得到这个字符串： 

```Node.js
var base64url = require('base64url')
var header = {
    "from_user": "B",
    "target_user": "A"
}
console.log(base64url(JSON.stringify(header)))
```

> 注：Base64是一种编码，也就是说，它是可以被翻译回原来的样子来的。它并不是一种加密过程。

#### **头部（Header）**

 JWT还需要一个头部，头部用于描述关于该JWT的最基本的信息，例如其类型以及签名所用的算法等。这也可以被表示成一个JSON对象： 

```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```

 在这里，我们说明了这是一个JWT，并且我们所用的签名算法（后面会提到）是HS256算法。

对它也要进行Base64编码，之后的字符串就成了JWT的Header（头部）： 

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
```

#### **签名（签名）**

 将上面的两个编码后的字符串都用句号.连接在一起（头部在前），就形成了： 

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWx
ob3N0OjgwMDFcL2F1dGhcL2xvZ2luIiwiaWF0IjoxNDUxODg4MTE5LCJleHAiOjE0NTQ1MTYxMTksIm5iZiI6MTQ1MTg4OD
ExOSwianRpIjoiMzdjMTA3ZTQ2MDlkZGJjYzljMDk2ZWE1ZWU3NmM2NjcifQ
```

 最后，我们将上面拼接完的字符串用HS256算法进行加密。在加密的时候，我们还需要提供一个密钥（secret）: 

```
HMACSHA256(
    base64UrlEncode(header) + "." +
    base64UrlEncode(payload),
    secret
)
```

 这样就可以得到我们加密后的内容： 

```
wyoQ95RjAyQ2FF3aj8EvCSaUmeP0KUqcCJDENNfnaT4
```

 这一部分又叫做签名。

最后将这一部分签名也拼接在被签名的字符串后面，我们就得到了完整的JWT： 

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWx
ob3N0OjgwMDFcL2F1dGhcL2xvZ2luIiwiaWF0IjoxNDUxODg4MTE5LCJleHAiOjE0NTQ1MTYxMTksIm5iZiI6MTQ1MTg4OD
ExOSwianRpIjoiMzdjMTA3ZTQ2MDlkZGJjYzljMDk2ZWE1ZWU3NmM2NjcifQ.wyoQ95RjAyQ2FF3aj8EvCSaUmeP0KUqcCJDENNfnaT
```

## 二、JWT破解与伪造

JSON Web Token（JWT）是一个非常轻巧的规范。这个规范允许我们使用JWT在用户和服务器之间传递安全可靠的信息。JWT常被用于前后端分离，可以和Restful API配合使用，常用于构建身份认证机制。

JWT的数据格式分为三个部分： headers , payloads，signature(签名)，它们使用`.`点号分割。

#### JWT示例：

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ImZhbHNlIn0.oe4qhTxvJB8nNAsFWJc7_m3UylVZzO3FwhkYuESAyUM`

#### 进行base64解密：

`{"alg":"HS256","typ":"JWT"}.{"admin":"falseIn0.¡î*<o$'4X;_u2Vs;qpF. 2UM`

伪造的目的就是将admin修改成ture，但是不是简单的修改然后base64加密，JWT会对其合法性进行token验证。

#### 验证方法：

首先服务端会产生一个`key`，然后以这个`key`作为密钥，使用第一部分选择的加密方式（这里就是`HS256`），对第一部分和第二部分`拼接的结果`进行加密，然后把加密结果放到`第三部分`。

第一部分：{"alg":"HS256","typ":"JWT"}

第二部分：{"admin":"false}

#### 提供一个破解key的工具

​	[C语言版JWT破解工具](https://github.com/brendan-rius/c-jwt-cracker)

​	下载后拖到kali中使用命令make编译

```
./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ImZhbHNlIn0.oe4qhTxvJB8nNAsFWJc7_m3UylVZzO3FwhkYuESAyUM	
```

基本上就是爆破了，下面是运行结果：

```bash
root@kali:~/桌面/c-jwt-cracker-master# ./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ImZhbHNlIn0.oe4qhTxvJB8nNAsFWJc7_m3UylVZzO3FwhkYuESAyUM
Secret is "54l7y"
```



#### 验证网站

​	https://jwt.io/#debugger-io

验证一下是否正确







## 其他资料

- https://www.shuzhiduo.com/A/Ae5RR3WN5Q/
- 