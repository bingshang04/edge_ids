# Edge-IDS - 基于TCN的轻量级边缘入侵检测系统

一个面向边缘计算场景的实时网络入侵检测系统，使用 **TCN（时序卷积网络）** 实现高精度、低延迟检测，专为资源受限设备优化。

## 核心亮点

- **高检测率**：UNSW-NB15 上召回率 **99.58%**，F1 **97.97%**
- **轻量化设计**：支持 INT8 量化，适用于树莓派5部署
- **实时性**：支持网卡实时抓包 + 模型推理
- **Web可视化**：实时仪表盘监控
- **跨平台**：Windows/Linux 开发机 + 树莓派5 部署

## 项目结构

```
edge_ids_refactored/
├── src/                      # 源代码
│   ├── config/              # 配置管理
│   │   ├── __init__.py
│   │   ├── constants.py     # 常量定义
│   │   └── settings.py      # 配置管理类
│   ├── capture/             # 数据包捕获
│   │   ├── __init__.py
│   │   └── packet_capture.py
│   ├── features/            # 特征提取
│   │   ├── __init__.py
│   │   └── flow_features.py
│   ├── inference/           # 推理检测
│   │   ├── __init__.py
│   │   └── detector.py
│   ├── models/              # 模型定义
│   │   ├── __init__.py
│   │   └── tcn_model.py
│   ├── utils/               # 工具函数
│   │   ├── __init__.py
│   │   ├── logger.py        # 日志管理
│   │   ├── exceptions.py    # 异常定义
│   │   ├── helpers.py       # 辅助函数
│   │   └── platform_info.py # 平台检测
│   └── web/                 # Web仪表盘
│       ├── __init__.py
│       └── dashboard.py
├── templates/               # HTML模板
│   └── dashboard.html
├── static/                  # 静态资源
│   ├── css/
│   │   └── dashboard.css
│   └── js/
│       └── dashboard.js
├── data/                    # 数据目录
│   └── models/             # 模型文件
├── logs/                    # 日志目录
├── config.yaml             # 主配置文件
├── requirements.txt        # 基础依赖
├── requirements-pc.txt     # PC完整依赖
├── requirements-pi.txt     # 树莓派依赖
└── main.py                 # 主程序入口
```

## 快速开始

### 1. 环境准备

```bash
# 克隆项目
cd edge_ids_refactored

# 创建虚拟环境（推荐）
python -m venv venv

# 激活虚拟环境
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 安装依赖
# PC版本:
pip install -r requirements-pc.txt

# 树莓派版本:
pip install -r requirements-pi.txt
```

### 2. 配置

编辑 `config.yaml` 文件，根据您的环境修改配置：

```yaml
# 修改网络接口
capture:
  interface: "eth0"  # 使用 `ip link` 查看可用接口

# 修改模型路径
model:
  model_path: "data/models/tcn_model_3.0.pth"

# 修改Web端口
web:
  port: 8080
```

### 3. 运行

```bash
# 完整模式（仪表盘 + 检测）
sudo python main.py --mode full

# 仅仪表盘模式
python main.py --mode dashboard

# 仅检测模式
sudo python main.py --mode capture --interface eth0

# 使用自定义配置
sudo python main.py --config my_config.yaml
```

> **注意**：数据包捕获需要 root 权限，请使用 `sudo` 运行。

### 4. 访问仪表盘

打开浏览器访问：`http://localhost:8080`

## 命令行参数

```
usage: main.py [-h] [--mode {full,capture,dashboard}] [--interface INTERFACE]
               [--config CONFIG] [--log-level {DEBUG,INFO,WARNING,ERROR}]

Edge-IDS 边缘入侵检测系统

optional arguments:
  -h, --help            显示帮助信息
  --mode {full,capture,dashboard}
                        运行模式（默认: full）
  --interface INTERFACE
                        网络接口名称（默认: eth0）
  --config CONFIG       配置文件路径（默认: config.yaml）
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        日志级别
```

## 配置说明

### 环境变量

可以通过环境变量覆盖配置：

```bash
export EDGE_IDS_INTERFACE="eth0"
export EDGE_IDS_MODEL_PATH="data/models/tcn_model_3.0.pth"
export EDGE_IDS_WEB_PORT="8080"
export EDGE_IDS_LOG_LEVEL="INFO"
export EDGE_IDS_CONFIDENCE_THRESHOLD="0.5"
```

### 平台自动适配

系统会自动检测运行平台（x86 PC / 树莓派），并应用相应的优化配置：

| 配置项 | x86 PC | 树莓派 |
|--------|--------|--------|
| batch_size | 64 | 16 |
| sequence_length | 20 | 10 |
| hidden_dim | 128 | 64 |
| num_layers | 3 | 2 |
| quantization | FP32 | INT8 |
| inference_threads | 8 | 4 |

## API接口

### 状态查询

```bash
# 获取系统状态
curl http://localhost:8080/api/status

# 获取系统信息
curl http://localhost:8080/api/system

# 获取资源使用
curl http://localhost:8080/api/resources

# 获取完整统计
curl http://localhost:8080/api/stats
```

### 控制接口

```bash
# 开始检测
curl -X POST http://localhost:8080/api/control/start

# 停止检测
curl -X POST http://localhost:8080/api/control/stop
```

## 日志

日志文件保存在 `logs/` 目录：

- `edge_ids.log` - 主日志文件
- `edge_ids.error.log` - 错误日志文件

## 开发指南

### 添加新的回调

```python
from src.capture.packet_capture import PacketCapture

capture = PacketCapture()

def my_callback(packet_info):
    print(f"Received: {packet_info.src_ip} -> {packet_info.dst_ip}")

capture.register_callback(my_callback)
capture.start_live_capture()
```

### 自定义检测器

```python
from src.inference.detector import IDSDetector

detector = IDSDetector(
    model_path="path/to/model.pth",
    confidence_threshold=0.5
)

import numpy as np
features = np.random.randn(39).astype(np.float32)
result = detector.predict(features)

print(f"Prediction: {result.prediction}")
print(f"Confidence: {result.confidence}")
print(f"Latency: {result.latency_ms}ms")
```

## 性能优化

### PC优化

- 使用CUDA加速（如果有NVIDIA显卡）
- 增加batch_size和sequence_length
- 禁用量化以保持精度

### 树莓派优化

- 使用INT8量化减少内存占用
- 降低sequence_length和batch_size
- 使用TFLite模型（如果可用）

## 故障排除

### 权限问题

```bash
# 数据包捕获需要root权限
sudo python main.py

# 或者设置cap权限
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)
```

### 接口不存在

```bash
# 查看可用接口
ip link

# 修改配置文件中的interface
```

### 模型加载失败

```bash
# 检查模型文件是否存在
ls -la data/models/

# 检查模型路径配置
cat config.yaml | grep model_path
```

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！
