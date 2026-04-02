from enum import Enum
from typing import Dict, Any

# 项目信息
PROJECT_NAME = "Edge-IDS"
PROJECT_VERSION = "1.0.0"
PROJECT_DESCRIPTION = "基于TCN的轻量级边缘入侵检测系统"

# 默认路径
DEFAULT_MODEL_PATH = "data/models/tcn_model_3.0.pth"
DEFAULT_LOG_DIR = "logs"
DEFAULT_DATA_DIR = "data"

# 网络协议
class ProtocolType(str, Enum):
    """协议类型枚举"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"

# TCP标志位
TCP_FLAGS = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR'
}

# 平台默认配置
PLATFORM_DEFAULTS: Dict[str, Dict[str, Any]] = {
    'raspberry_pi': {
        'batch_size': 16,
        'sequence_length': 10,
        'hidden_dim': 64,
        'num_layers': 2,
        'use_tflite': True,
        'quantization': 'INT8',
        'max_memory_mb': 2048,
        'inference_threads': 4,
        'learning_rate': 0.001,
        'kernel_size': 3,
        'dropout': 0.2,
    },
    'x86_pc': {
        'batch_size': 64,
        'sequence_length': 20,
        'hidden_dim': 128,
        'num_layers': 3,
        'use_tflite': False,
        'quantization': 'FP32',
        'max_memory_mb': 8192,
        'inference_threads': 8,
        'learning_rate': 0.001,
        'kernel_size': 3,
        'dropout': 0.2,
    }
}

# 特征提取配置
FEATURE_CONFIG = {
    'flow_timeout': 120.0,  # 流超时时间（秒）
    'max_flows': 10000,      # 最大活跃流数
    'feature_dim': 39,       # 特征维度
    'packet_history_size': 1000,  # 包历史记录大小
    'iat_history_size': 100,      # IAT历史记录大小
}

# 检测器配置
DETECTOR_CONFIG = {
    'confidence_threshold': 0.5,
    'alert_threshold': 0.8,
    'inference_buffer_size': 100,  # 推理时间统计缓冲区大小
}

# Web服务器配置
WEB_CONFIG = {
    'host': '0.0.0.0',
    'port': 8080,
    'debug': False,
}

# 数据包捕获配置
CAPTURE_CONFIG = {
    'interface': 'eth0',
    'bpf_filter': 'ip',
    'buffer_size': 65536,
    'promiscuous': True,
    'queue_size': 10000,
}

# 日志配置
LOG_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    'date_format': '%Y-%m-%d %H:%M:%S',
    'max_bytes': 10 * 1024 * 1024,  # 10MB
    'backup_count': 5,
}
