# Edge-IDS 重构说明

## 重构概述

本次重构对Edge-IDS项目进行了全面的架构优化和代码改进，主要目标是：

1. **统一配置管理** - 集中式配置系统，支持YAML文件、环境变量和代码配置
2. **统一日志系统** - 结构化日志管理，支持控制台和文件输出
3. **完善错误处理** - 自定义异常体系，提供详细的错误信息
4. **代码模块化** - 清晰的模块划分，提高代码复用性
5. **性能优化** - 改进数据结构和算法，提升运行效率
6. **Web仪表盘优化** - 分离模板和逻辑，提供更好的用户体验

## 主要改进

### 1. 配置管理模块 (`src/config/`)

**新增文件：**
- `settings.py` - 配置管理类，支持单例模式
- `constants.py` - 常量定义

**特性：**
- 支持从YAML文件加载配置
- 支持环境变量覆盖
- 自动平台检测和适配
- 配置验证和类型转换

**使用示例：**
```python
from src.config import get_settings

config = get_settings('config.yaml')
print(config.capture.interface)
print(config.model.model_path)
```

### 2. 日志系统 (`src/utils/logger.py`)

**改进：**
- 统一的日志配置
- 彩色控制台输出
- 自动日志轮转
- 分离错误日志

**使用示例：**
```python
from src.utils.logger import get_logger

logger = get_logger(__name__)
logger.info("信息日志")
logger.error("错误日志")
```

### 3. 异常处理 (`src/utils/exceptions.py`)

**新增异常类：**
- `EdgeIDSException` - 基础异常
- `ConfigError` - 配置错误
- `ModelError` - 模型错误
- `CaptureError` - 捕获错误
- `FeatureError` - 特征错误
- `InferenceError` - 推理错误

### 4. 数据包捕获模块 (`src/capture/packet_capture.py`)

**改进：**
- 更好的错误处理
- 性能统计
- 队列管理
- 回调机制优化

### 5. 特征提取模块 (`src/features/flow_features.py`)

**改进：**
- 特征枚举定义
- 流状态管理优化
- 定期清理过期流
- 统计信息收集

### 6. 推理检测模块 (`src/inference/detector.py`)

**改进：**
- 检测结果数据类
- 设备自动选择（CPU/CUDA）
- 批量预测支持
- 模型导出功能

### 7. TCN模型 (`src/models/tcn_model.py`)

**改进：**
- 权重初始化
- 特征表示提取
- 概率预测
- 模型信息获取

### 8. 平台检测 (`src/utils/platform_info.py`)

**改进：**
- 平台类型枚举
- 系统信息获取
- 资源配置
- 性能监控

### 9. Web仪表盘 (`src/web/dashboard.py`)

**改进：**
- 分离HTML模板
- RESTful API设计
- 实时状态更新
- 控制接口

### 10. 主程序 (`main.py`)

**改进：**
- 面向对象设计
- 组件生命周期管理
- 信号处理
- 统计信息输出

## 文件结构对比

### 重构前
```
project/
├── packet_capture.py
├── flow_features.py
├── detector.py
├── tcn_model.py
├── platform_info.py
├── dashboard.py
├── main.py
├── config.yaml
└── requirements.txt
```

### 重构后
```
edge_ids_refactored/
├── src/                      # 源代码
│   ├── config/              # 配置管理
│   ├── capture/             # 数据包捕获
│   ├── features/            # 特征提取
│   ├── inference/           # 推理检测
│   ├── models/              # 模型定义
│   ├── utils/               # 工具函数
│   └── web/                 # Web仪表盘
├── templates/               # HTML模板
├── static/                  # 静态资源
├── data/models/            # 模型文件
├── logs/                   # 日志目录
├── config.yaml             # 主配置
├── config-pc.yaml          # PC配置
├── config-pi.yaml          # 树莓派配置
├── requirements.txt        # 基础依赖
├── requirements-pc.txt     # PC依赖
├── requirements-pi.txt     # 树莓派依赖
├── main.py                 # 主程序
├── run.sh                  # 启动脚本
└── README.md               # 使用说明
```

## 迁移指南

### 1. 配置文件迁移

原 `config.yaml` 可以直接使用，新增了一些可选配置项：

```yaml
# 新增配置项
capture:
  queue_size: 10000        # 新增

features:
  packet_history_size: 1000  # 新增
  iat_history_size: 100      # 新增

inference:
  buffer_size: 100         # 新增

logging:
  log_dir: "logs"          # 新增
  max_bytes: 10485760      # 新增
  backup_count: 5          # 新增
```

### 2. 代码迁移

如果你的代码直接导入了原模块，需要更新导入路径：

**原代码：**
```python
from packet_capture import PacketCapture
from flow_features import FeatureExtractor
from detector import IDSDetector
```

**新代码：**
```python
from src.capture.packet_capture import PacketCapture
from src.features.flow_features import FeatureExtractor
from src.inference.detector import IDSDetector
```

### 3. 模型文件

模型文件位置保持不变：`data/models/tcn_model_3.0.pth`

## 新增功能

### 1. 启动脚本 (`run.sh`)

```bash
# 快速启动
./run.sh

# 指定模式
./run.sh --mode dashboard

# 指定接口
./run.sh --interface wlan0
```

### 2. 环境变量支持

```bash
export EDGE_IDS_INTERFACE="eth0"
export EDGE_IDS_MODEL_PATH="data/models/tcn_model_3.0.pth"
export EDGE_IDS_WEB_PORT="8080"
export EDGE_IDS_LOG_LEVEL="DEBUG"
```

### 3. API接口

```bash
# 获取状态
curl http://localhost:8080/api/status

# 获取资源使用
curl http://localhost:8080/api/resources

# 控制检测
curl -X POST http://localhost:8080/api/control/start
curl -X POST http://localhost:8080/api/control/stop
```

## 性能改进

1. **队列管理** - 防止内存无限增长
2. **定期清理** - 自动清理过期流
3. **统计优化** - 使用deque限制历史记录大小
4. **设备选择** - 自动选择最优计算设备

## 已知问题

1. **Scapy依赖** - 需要root权限运行
2. **PyTorch ARM** - 树莓派上可能需要手动编译
3. **TFLite** - 可选依赖，需要单独安装

## 后续优化建议

1. 添加数据库支持，持久化检测记录
2. 实现分布式部署支持
3. 添加更多可视化图表
4. 支持更多模型格式（ONNX, TFLite）
5. 添加告警通知功能（邮件、Webhook）
