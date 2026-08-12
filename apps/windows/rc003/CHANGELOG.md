# Changelog — Remote Mic RC003 (Windows)

本项目按“候选发布”打标签。内部构建版本号固定在
`installer/RemoteMicRC003Setup.iss` 的 `AppVersion`（当前 `0.1.0-candidate`），
仓库级 tag 只作为发布编号，两者对应关系以每条发布说明为准。

标签格式：`v<内部版本>-windows-rc003-candidate.<序号>`。

## [0.1.9-local] — 2026-08-12

松手后的 HID 尾随边沿修订：

- 以 ATVV `AUDIO_STARTED`/麦克风控制会话作为 HOLD 模式的权威生命周期；
  物理 F5 只在当前会话正等待该边沿时才会转换为配置的语音热键。
- 吞掉 `AUDIO_STOP` 之后 Windows/RC003 HID 偶发的迟到、仅按下 F5，避免
  已经正常释放的 Ctrl+Win 被再次按住并等待 watchdog 强制释放。
- 保留音频先到、F5 后到的低延迟路径；如果下一次真正按压的 F5 先于 ATVV
  事件到达，现有 0.4 秒 ATVV fallback 仍会完成激活，不会让语音入口失效。
- 新增完整的“正常启动 → 真实停止 → F5 尾随按下 → 下一 ATVV 会话重新武装”
  回归覆盖。

## [0.1.8-local] — 2026-08-12

长语音流续期修订：

- 补齐 ATVV 1.0 主机端 `AUDIO_EXTEND`（`0x0E + stream_id`）续期命令。
  音频流活跃时每 5 秒刷新一次遥控器固件的传输超时，收到真实
  `AUDIO_STOP`、断连或连接清理时立即取消，避免用户尚未说完时被遥控器
  自身的 15/30 秒固件计时器提前结束。
- 续期任务绑定当前 BLE generation，并在 GATT 资源释放前取消、等待完成，
  避免旧连接的延迟写入落到重连后的新会话。
- 保留并记录 ATVV `AUDIO_START` 的交互模式和 stream id，以及
  `AUDIO_STOP` 的原始原因码（例如 `0x08 = audio_transfer_timeout`），便于
  实机区分超时、真实按键释放和通知关闭。
- 新增协议命令、原因码、周期续期与停止取消的回归测试。

## [0.1.7-local] — 2026-08-12

本地长语音结束后的按键状态修订：

- 修复一次语音流结束后，后续按压未收到新的音频/控制事件、watchdog 虽已
  释放 Ctrl/Win 却遗留 `trigger already in progress` 标记的问题；安全释放
  现在会在同一语音状态锁内清除全部待处理触发和 fallback 状态。
- watchdog 释放时继续记住尚未收到 F5-up 的真实长按，避免 Windows 的 F5
  auto-repeat 被误判为一次新按压；真实 F5-up 或完整连接清理再解除该物理锁存。
- 新增“无音频的后续按压 → watchdog → auto-repeat → 真实释放 → 下一次按压”
  的完整回归测试。

## [0.1.6-local] — 2026-08-12

本地语音触发去重修订：

- 修复 `AudioStarted` 先于物理 F5 到达时，已完成一次豆包激活后仍保留
  0.4 秒 host fallback、继而再次激活的问题。真实 F5 按下边沿现在会在
  语音状态锁内清除等待标记并取消兜底计时器；已经进入回调队列的旧计时器
  也会因标记已清除而保持静默。
- 新增针对“音频先到、F5 后到”的竞态回归测试，确认一个物理按压只进入
  一次语音触发路径。

## [0.1.5-local] — 2026-08-12

本地豆包权限与键盘安全修订：

- 主桥接继续以普通用户权限运行；当豆包的 SYSTEM/高完整性
  `ImeService.exe` 对普通 Frida 枚举不可见时，只通过一次 UAC 启动隐藏的
  豆包物理化助手。助手不启动 BLE、Raw Input、音频或全局旧键抑制器，且
  绑定主桥接 PID，主桥接退出后自动卸载并退出。
- 提权助手用随机命名事件回报“已附加/失败”，并核对父 PID 的可执行文件必须
  与助手自身完全相同；不会写入调用方指定的高权限文件。
- 豆包内的 Frida 过滤器新增 `dwExtraInfo == RemoteMic 私有标记` 条件。现在
  只有 RemoteMic 自己的目标热键事件会清除 `LLKHF_INJECTED`；其他程序的
  合成 Ctrl/Win 保持原样。
- 新增助手参数边界、源码/冻结命令、UAC 子进程复用/失败清理和隐藏入口路由
  回归测试。

## [0.1.4-local] — 2026-08-12

本地 RC003 / 豆包输入法兼容修订：

- 为当前 `ImeService.exe` 精确哈希
  `86a863fd2b4be9526ab3cd88a857ba6354b8547e0b39319d950563cad3827435`
  增加已静态核对的 `WH_KEYBOARD_LL` 回调 RVA `0x744520`，使自定义
  `lctrl+lwin` 语音热键可进入豆包的物理化路径；未知版本仍拒绝附加。
- 低层遥控器/实体键关联等待上限从 60ms 降到 40ms，逐键诊断日志降为
  DEBUG，避免常驻桥接拖慢 Enter/方向键并持续刷写日志。
- HOLD 模式无音频卡键 watchdog 从 5 秒缩短到 1.5 秒；正常语音帧持续
  续期，丢失 F5-up / AudioStopped 时更快释放 Ctrl/Win。

## [0.1.0-candidate] — 2026-07-31

标签：`v0.1.0-windows-rc003-candidate.1`（基于 `6c33fcc`）

首个 Windows RC003 候选发布。本版本已在真实 RC003 遥控器上完成逐键、
语音链路验收（详见 README“真机验收”部分）。CI 与自动构建仍然不能
替代真机验证。

### 新增

- **Frida HID tap 旁路**：对 Windows 普通输入链路拿不到的返回、音量+、
  音量- 缺失 usages（`0xF1`、`0x80`、`0x81`），复用上游
  `remote-bridge-hub` 的 Frida Gadget WUDFHost tap 读取；扩展为上报
  遥控器全部键盘 usage，作为所有普通按键的输入旁路。Gadget 是可选的
  第三方二进制，需显式获取（`build/fetch-frida-gadget.ps1`）且验证
  固定 SHA-256 后才会启用。
- **豆包语音触发（DoubaoPhysicalizer）**：注入的右 Alt 合成事件此前被
  豆包输入法 `ImeService` 的低层键盘钩子以 `LLKHF_INJECTED` 标志忽略；
  现在附加到 `ImeService.exe` 的低层回调，只对该标记事件清除 injected /
  lower-integrity 标志并清空 `dwExtraInfo`，使豆包看到的按键形状与
  实体右 Alt 一致。默认按住模式 `ralt`、切换模式 `ralt+space`。
- **设置页独立入口**：`RemoteMicRC003Settings.exe` 与桥接 EXE 分离
  （后合并为单个 EXE，见下）。
- **按键采集/回放工具**：`src/rc003_key_test.py`、`rc003_key_probe.py`
  等诊断工具，被动记录真实物理签名，不执行映射动作。

### 修复

- **普通按键双触发**：方向键、OK 等按键按下时一次动作被触发两次。
  根因是低层键盘钩子阻塞了 `WM_INPUT` 派发，导致“先 arm 后吞键”的
  等待式方案永远慢半拍。改为由 Frida GATT tap 的独立 socket 线程在
  `NtDeviceIoControlFile` 报告到达时 arm，低层钩子零等待匹配并吞掉
  原生按键，只注入一次映射动作。方向/OK/Home/Menu/TV/Power/返回/
  音量键全部实测通过。
- **F5 语音键重复替换刷屏**：按住麦克风键期间键盘 auto-repeat 会让
  “替换为右 Alt”逻辑反复触发；为 transform 增加已按下/已发送守卫，
  只在真实按下/释放边沿各发送一次。
- **BLE GATT 特征找不到**：修复后反复出现
  `ATVV characteristic not found`；改用 `BluetoothCacheMode.UNCACHED`
  读取服务与特征，避免 Windows 缓存旧枚举结果。
- **设置保存失败且映射不生效**：配置文件改为临时文件 + fsync +
  `os.replace` 原子写入；Qt 设置保存捕获一切持久化/回读异常并在界面
  显示错误；桥接进程在按键前按 mtime 热加载新的按键映射，磁盘数据
  损坏时保留最后一份有效映射。
- **启动闪黑色命令行窗口**：桥接启动子进程与打包运行时的控制台子进程
  均使用 `CREATE_NO_WINDOW` 隐藏。
- **语音识别无声/不稳定**：语音输出改为按端点能力输出立体声并复制
  声道；解码后增加 20 Hz 一阶高通 DC 阻挡；默认增益提高到 +10 dB；
  16 kHz → 48 kHz 改有状态连续插值（对齐上游）。实机验收：豆包输入法
  能识别遥控器语音。

### 变更

- **单 EXE 行为**：合并为同一个 `RemoteMicRC003.exe`。双击（无参数）或
  `--settings` 打开设置窗口；`--bridge` 显式启动桥接进程。安装器/便携版
  的启动快捷方式统一使用 `--bridge`。
- **设置保存原子化**：`save_config` / `save_key_bindings` 走原子写入，
  不暴露半写的 JSON。
- **返回键默认映射**：保持 `delete_backward`（退格）语义；新增可选的
  “浏览器后退”动作供用户在设置页手动绑定。
- 普通按键仍通过 `SendInput` 注入映射动作；语音快捷键通过物理化的
  右 Alt 事件；两者互不混用。

### 已知限制

- 未签名，首次运行会触发 SmartScreen 提示，属预期行为。
- Frida Gadget 与 VB-CABLE 均为可选第三方组件；未显式获取/安装时，
  缺失 usages 不会被猜测伪造，语音默认没有虚拟麦克风路由。
- 遥控器没有独立物理静音键；“系统静音”只是可选手动绑定。
- 安装器与便携版运行期配置都写入 `%LOCALAPPDATA%\RemoteMic\RC003`，
  卸载不会自动删除。
