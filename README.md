# XJTU网页认证登录

## 适用范围

* 适用于创新港web protal认证系统
* 可能适用于兴庆STU无线认证系统(未测试)

## 依赖

* pycryptodome

## 用法

```python
from login import IHarbourNet
login_client=IHarbourNet()
if not log.testOnline():
    login_client.login('你的账号','你的密码')
```
