import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

from .constants import (
    PROJECT_NAME, PROJECT_VERSION, DEFAULT_MODEL_PATH, DEFAULT_LOG_DIR,
    PLATFORM_DEFAULTS, FEATURE_CONFIG, DETECTOR_CONFIG, WEB_CONFIG,
    CAPTURE_CONFIG, LOG_CONFIG
)

logger = logging.getLogger(__name__)


@dataclass
class ModelConfig:
    """模型配置"""
    input_dim: int = 39
    num_classes: int = 2
    num_channels: list = field(default_factory=lambda: [128, 256])
    kernel_size: int = 3
    dropout: float = 0.2
    model_path: str = DEFAULT_MODEL_PATH


@dataclass
class CaptureConfig:
    """数据包捕获配置"""
    interface: str = 'eth0'
    bpf_filter: str = 'ip'
    buffer_size: int = 65536
    promiscuous: bool = True
    queue_size: int = 10000


@dataclass
class FeatureConfig:
    """特征提取配置"""
    flow_timeout: float = 120.0
    max_flows: int = 10000
    feature_dim: int = 39
    packet_history_size: int = 1000
    iat_history_size: int = 100


@dataclass
class InferenceConfig:
    """推理配置"""
    confidence_threshold: float = 0.5
    alert_threshold: float = 0.8
    sequence_length: int = 20
    batch_size: int = 64
    buffer_size: int = 100


@dataclass
class WebConfig:
    """Web服务器配置"""
    host: str = '0.0.0.0'
    port: int = 8080
    debug: bool = False


@dataclass
class LogConfig:
    """日志配置"""
    level: str = 'INFO'
    format: str = '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s'
    date_format: str = '%Y-%m-%d %H:%M:%S'
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5
    log_dir: str = DEFAULT_LOG_DIR


class Settings:
    """
    统一配置管理类
    
    支持从YAML文件加载配置，并提供默认值
    """
    
    _instance: Optional['Settings'] = None
    
    def __new__(cls, *args, **kwargs):
        """单例模式"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config_path: Optional[str] = None):
        if self._initialized:
            return
            
        self._initialized = True
        self._config_path = config_path
        self._platform_type = self._detect_platform()
        
        # 初始化各模块配置
        self.model = ModelConfig()
        self.capture = CaptureConfig()
        self.feature = FeatureConfig()
        self.inference = InferenceConfig()
        self.web = WebConfig()
        self.log = LogConfig()
        
        # 平台特定配置
        self.platform: Dict[str, Any] = {}
        
        # 加载配置
        self._load_config()
        
        logger.debug(f"Settings initialized with platform: {self._platform_type}")
    
    def _detect_platform(self) -> str:
        """检测运行平台"""
        import platform
        machine = platform.machine().lower()
        
        if 'arm' in machine or 'aarch64' in machine:
            return 'raspberry_pi'
        elif 'x86_64' in machine or 'amd64' in machine:
            return 'x86_pc'
        else:
            logger.warning(f"Unknown platform: {machine}, using x86_pc defaults")
            return 'x86_pc'
    
    def _load_config(self):
        """加载配置文件"""
        # 首先应用平台默认配置
        self._apply_platform_defaults()
        
        # 然后加载YAML配置文件（如果存在）
        if self._config_path and os.path.exists(self._config_path):
            try:
                with open(self._config_path, 'r', encoding='utf-8') as f:
                    config_data = yaml.safe_load(f)
                
                if config_data:
                    self._apply_yaml_config(config_data)
                    logger.info(f"Loaded configuration from {self._config_path}")
            except Exception as e:
                logger.error(f"Failed to load config from {self._config_path}: {e}")
        
        # 最后应用环境变量覆盖
        self._apply_env_overrides()
    
    def _apply_platform_defaults(self):
        """应用平台默认配置"""
        defaults = PLATFORM_DEFAULTS.get(self._platform_type, PLATFORM_DEFAULTS['x86_pc'])
        
        self.platform = {
            'type': self._platform_type,
            **defaults
        }
        
        # 应用到各模块配置
        self.inference.sequence_length = defaults['sequence_length']
        self.inference.batch_size = defaults['batch_size']
        self.model.num_channels = [defaults['hidden_dim']] * defaults['num_layers']
        self.model.kernel_size = defaults['kernel_size']
        self.model.dropout = defaults['dropout']
    
    def _apply_yaml_config(self, config_data: Dict[str, Any]):
        """应用YAML配置"""
        # 模型配置
        if 'model' in config_data:
            model_cfg = config_data['model']
            for key, value in model_cfg.items():
                if hasattr(self.model, key):
                    setattr(self.model, key, value)
        
        # 捕获配置
        if 'capture' in config_data:
            cap_cfg = config_data['capture']
            for key, value in cap_cfg.items():
                if hasattr(self.capture, key):
                    setattr(self.capture, key, value)
        
        # 特征配置
        if 'features' in config_data:
            feat_cfg = config_data['features']
            for key, value in feat_cfg.items():
                if hasattr(self.feature, key):
                    setattr(self.feature, key, value)
        
        # 推理配置
        if 'inference' in config_data:
            inf_cfg = config_data['inference']
            for key, value in inf_cfg.items():
                if hasattr(self.inference, key):
                    setattr(self.inference, key, value)
        
        # Web配置
        if 'web' in config_data:
            web_cfg = config_data['web']
            for key, value in web_cfg.items():
                if hasattr(self.web, key):
                    setattr(self.web, key, value)
        
        # 日志配置
        if 'logging' in config_data:
            log_cfg = config_data['logging']
            for key, value in log_cfg.items():
                if hasattr(self.log, key):
                    setattr(self.log, key, value)
    
    def _apply_env_overrides(self):
        """应用环境变量覆盖"""
        env_mappings = {
            'EDGE_IDS_INTERFACE': ('capture', 'interface'),
            'EDGE_IDS_MODEL_PATH': ('model', 'model_path'),
            'EDGE_IDS_WEB_PORT': ('web', 'port'),
            'EDGE_IDS_LOG_LEVEL': ('log', 'level'),
            'EDGE_IDS_CONFIDENCE_THRESHOLD': ('inference', 'confidence_threshold'),
        }
        
        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                config_obj = getattr(self, section)
                # 尝试类型转换
                try:
                    current_value = getattr(config_obj, key)
                    if isinstance(current_value, int):
                        value = int(value)
                    elif isinstance(current_value, float):
                        value = float(value)
                    elif isinstance(current_value, bool):
                        value = value.lower() in ('true', '1', 'yes', 'on')
                except (ValueError, AttributeError):
                    pass
                
                setattr(config_obj, key, value)
                logger.debug(f"Override {section}.{key} from environment variable {env_var}")
    
    @property
    def platform_type(self) -> str:
        """获取平台类型"""
        return self._platform_type
    
    @property
    def is_raspberry_pi(self) -> bool:
        """是否在树莓派上运行"""
        return self._platform_type == 'raspberry_pi'
    
    @property
    def is_x86_pc(self) -> bool:
        """是否在x86电脑上运行"""
        return self._platform_type == 'x86_pc'
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'platform': self.platform,
            'model': self.model.__dict__,
            'capture': self.capture.__dict__,
            'feature': self.feature.__dict__,
            'inference': self.inference.__dict__,
            'web': self.web.__dict__,
            'log': self.log.__dict__,
        }
    
    def save_to_yaml(self, path: str):
        """保存配置到YAML文件"""
        try:
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump(self.to_dict(), f, default_flow_style=False, allow_unicode=True)
            logger.info(f"Configuration saved to {path}")
        except Exception as e:
            logger.error(f"Failed to save config to {path}: {e}")


def get_settings(config_path: Optional[str] = None) -> Settings:
    """
    获取Settings单例实例
    
    Args:
        config_path: 配置文件路径（可选）
    
    Returns:
        Settings实例
    """
    return Settings(config_path)
