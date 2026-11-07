# 冻结进程 FreezeProcess

Windows 进程冻结工具。跑一次把程序冻住，再运行一次解冻。

| 文件 | 说明 |
| --- | --- |
| `FreezeProcessV1.0.py` | 当前版本。整个进程冻结，游戏不会弹"失去响应" |
| `冻结进程V0.1.py` | 旧版。只冻业务线程、保留窗口线程，普通程序可用 |
| `冻结进程.md` | 项目文档：两个版本的差异、原理、参数、限制、FAQ |

## 快速开始

需要 Python 3（只用标准库 `ctypes`，无需安装任何第三方包）。

改脚本第 32 行的 `TARGET`：

```python
TARGET = "PBZ.exe"      # 换成你的程序名，不带 .exe 也行
```

然后运行：

```powershell
python FreezeProcessV1.0.py          # 第一次 = 冻结，再运行一次 = 解冻
```

常用参数：

```powershell
python FreezeProcessV1.0.py --list          # 只看状态，不动手
python FreezeProcessV1.0.py --pid 6900      # 按 PID 指定，同名多开时用
python FreezeProcessV1.0.py --target game.exe
```

完整说明见 [冻结进程.md](冻结进程.md)。

## 它是怎么做的

V1.0 分四步：

1. `ITaskbarList.DeleteTab` 摘掉任务栏按钮
2. `WS_EX_TOOLWINDOW` 让窗口脱离 Alt+Tab
3. `ShowWindow(SW_HIDE)` 隐藏窗口
4. `NtSuspendProcess` 冻结全部线程

窗口藏起来之后 Windows 没有对象可以判定"未响应"，所以不会弹那个框，也不会有红色的任务栏标记。

解冻时按冻结前记录的 `EXSTYLE` 和显示状态原样还原，再把任务栏按钮挂回去。

## 注意

- 冻结期间进程不占 CPU，但**内存和显存不释放**
- 网络连接会超时，联机游戏冻久了会掉线
- 反作弊驱动通常会拒绝这类操作，不建议在联机游戏使用
- 脚本没有白名单保护，别拿它冻系统关键进程

## 环境

- Windows 10 / 11
- Python 3.7+
- 已验证：Windows 11 25H2 build 26200 + Python 3.11.9

## License

MIT
