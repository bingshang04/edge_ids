import time
import numpy as np
import torch
import torch.nn as nn
from dataclasses import dataclass
from collections import deque
from typing import Optional, List, Dict, Any, Tuple, Union
from pathlib import Path

from ..utils.logger import LoggerMixin
from ..utils.exceptions import ModelError, ModelNotFoundError, ModelLoadError, InferenceError
from ..utils.helpers import clamp
from ..models.tcn_model import TCN


@dataclass
class DetectionResult:
    """检测结果数据类"""
    prediction: int           # 预测类别（0=正常，1=攻击）
    confidence: float         # 置信度
    probability: float        # 攻击概率
    latency_ms: float         # 推理延迟（毫秒）
    timestamp: float          # 检测时间戳
    
    def is_attack(self, threshold: float = 0.5) -> bool:
        """判断是否攻击"""
        return self.prediction == 1 and self.confidence >= threshold
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'prediction': self.prediction,
            'confidence': round(self.confidence, 4),
            'probability': round(self.probability, 4),
            'latency_ms': round(self.latency_ms, 2),
            'timestamp': self.timestamp,
            'is_attack': self.is_attack()
        }


class IDSDetector(LoggerMixin):
    """
    实时入侵检测器
    
    支持PyTorch模型和TFLite模型，提供实时推理能力
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        input_dim: int = 39,
        num_classes: int = 2,
        sequence_length: int = 20,
        num_channels: Optional[List[int]] = None,
        kernel_size: int = 3,
        dropout: float = 0.2,
        confidence_threshold: float = 0.5,
        alert_threshold: float = 0.8,
        use_quantization: bool = False,
        device: Optional[str] = None
    ):
        """
        初始化检测器
        
        Args:
            model_path: 模型文件路径
            input_dim: 输入特征维度
            num_classes: 输出类别数
            sequence_length: 序列长度
            num_channels: TCN通道数列表
            kernel_size: 卷积核大小
            dropout: Dropout概率
            confidence_threshold: 置信度阈值
            alert_threshold: 告警阈值
            use_quantization: 是否使用量化
            device: 计算设备（'cpu', 'cuda', 或 None自动选择）
        """
        super().__init__()
        
        self.input_dim = input_dim
        self.num_classes = num_classes
        self.sequence_length = sequence_length
        self.confidence_threshold = confidence_threshold
        self.alert_threshold = alert_threshold
        self.use_quantization = use_quantization
        
        # 设置设备
        self.device = self._setup_device(device)
        
        # 初始化模型
        self.model = self._load_model(
            model_path=model_path,
            num_channels=num_channels,
            kernel_size=kernel_size,
            dropout=dropout
        )
        
        # 特征缓冲区
        self._feature_buffer: deque = deque(maxlen=sequence_length)
        
        # 性能统计
        self._inference_times: deque = deque(maxlen=100)
        self._detection_count = 0
        self._attack_count = 0
        
        self.logger.info(f"IDSDetector initialized: device={self.device}")
    
    def _setup_device(self, device: Optional[str]) -> torch.device:
        """
        设置计算设备
        
        Args:
            device: 设备名称
        
        Returns:
            torch.device对象
        """
        if device:
            return torch.device(device)
        
        # 自动选择
        if torch.cuda.is_available():
            device = torch.device('cuda')
            self.logger.info(f"Using CUDA device: {torch.cuda.get_device_name(0)}")
        else:
            device = torch.device('cpu')
            self.logger.info("Using CPU device")
        
        return device
    
    def _load_model(
        self,
        model_path: Optional[str],
        num_channels: Optional[List[int]],
        kernel_size: int,
        dropout: float
    ) -> nn.Module:
        """
        加载模型
        
        Args:
            model_path: 模型文件路径
            num_channels: 通道数列表
            kernel_size: 卷积核大小
            dropout: Dropout概率
        
        Returns:
            加载的模型
        """
        # 创建模型
        model = TCN(
            input_dim=self.input_dim,
            num_classes=self.num_classes,
            num_channels=num_channels or [128, 256],
            kernel_size=kernel_size,
            dropout=dropout
        )
        
        # 加载权重
        if model_path:
            model_path = Path(model_path)
            if not model_path.exists():
                self.logger.warning(f"Model file not found: {model_path}")
                self.logger.info("Using untrained model")
            else:
                try:
                    state_dict = torch.load(model_path, map_location=self.device)
                    model.load_state_dict(state_dict)
                    self.logger.info(f"Loaded model from {model_path}")
                except RuntimeError as e:
                    self.logger.error(f"Failed to load model: {e}")
                    self.logger.info("Using untrained model")
        else:
            self.logger.info("No model path provided, using untrained model")
        
        # 应用量化
        if self.use_quantization:
            model = torch.quantization.quantize_dynamic(
                model, {nn.Linear}, dtype=torch.qint8
            )
            self.logger.info("Applied INT8 dynamic quantization")
        
        # 移动到设备并设置为评估模式
        model = model.to(self.device)
        model.eval()
        
        return model
    
    def _preprocess(self, features: np.ndarray) -> torch.Tensor:
        """
        预处理特征
        
        Args:
            features: 输入特征数组
        
        Returns:
            预处理后的张量
        """
        # 确保正确的维度
        if len(features) != self.input_dim:
            raise InferenceError(
                f"Feature dimension mismatch: expected {self.input_dim}, got {len(features)}"
            )
        
        # 归一化
        features = (features - features.mean()) / (features.std() + 1e-8)
        
        # 添加到缓冲区
        self._feature_buffer.append(features)
        
        # 填充序列
        while len(self._feature_buffer) < self.sequence_length:
            self._feature_buffer.append(features)
        
        # 构建输入张量 (1, seq_len, features)
        sequence = np.array(list(self._feature_buffer)[-self.sequence_length:])
        tensor = torch.FloatTensor(sequence).unsqueeze(0)
        
        return tensor.to(self.device)
    
    def predict(self, features: np.ndarray) -> DetectionResult:
        """
        预测单条样本
        
        Args:
            features: 输入特征数组
        
        Returns:
            检测结果
        """
        start_time = time.time()
        
        try:
            # 预处理
            input_tensor = self._preprocess(features)
            
            # 推理
            with torch.no_grad():
                outputs = self.model(input_tensor)
                probabilities = torch.softmax(outputs, dim=1)
            
            # 获取预测结果
            probs = probabilities.cpu().numpy()[0]
            attack_prob = probs[1]
            normal_prob = probs[0]
            
            # 确定预测类别和置信度
            if attack_prob > normal_prob:
                prediction = 1
                confidence = attack_prob
            else:
                prediction = 0
                confidence = normal_prob
            
            # 计算延迟
            latency_ms = (time.time() - start_time) * 1000
            
            # 更新统计
            self._inference_times.append(latency_ms)
            self._detection_count += 1
            if prediction == 1:
                self._attack_count += 1
            
            return DetectionResult(
                prediction=prediction,
                confidence=float(confidence),
                probability=float(attack_prob),
                latency_ms=latency_ms,
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            raise InferenceError(f"Prediction failed: {e}")
    
    def predict_batch(self, features_batch: List[np.ndarray]) -> List[DetectionResult]:
        """
        批量预测
        
        Args:
            features_batch: 特征数组列表
        
        Returns:
            检测结果列表
        """
        results = []
        for features in features_batch:
            result = self.predict(features)
            results.append(result)
        return results
    
    def reset_buffer(self):
        """重置特征缓冲区"""
        self._feature_buffer.clear()
        self.logger.debug("Feature buffer reset")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        获取检测统计信息
        
        Returns:
            统计信息字典
        """
        if not self._inference_times:
            return {
                'total_detections': 0,
                'attack_count': 0,
                'avg_latency_ms': 0.0,
                'max_latency_ms': 0.0,
                'min_latency_ms': 0.0,
                'p95_latency_ms': 0.0,
            }
        
        times = list(self._inference_times)
        return {
            'total_detections': self._detection_count,
            'attack_count': self._attack_count,
            'attack_ratio': self._attack_count / max(self._detection_count, 1),
            'avg_latency_ms': round(np.mean(times), 2),
            'max_latency_ms': round(np.max(times), 2),
            'min_latency_ms': round(np.min(times), 2),
            'p95_latency_ms': round(np.percentile(times, 95), 2),
        }
    
    def save_model(self, path: str):
        """
        保存模型
        
        Args:
            path: 保存路径
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.model.state_dict(), path)
        self.logger.info(f"Model saved to {path}")
    
    def export_to_onnx(self, path: str, dummy_input: Optional[torch.Tensor] = None):
        """
        导出为ONNX格式
        
        Args:
            path: 导出路径
            dummy_input: 示例输入（可选）
        """
        if dummy_input is None:
            dummy_input = torch.randn(1, self.sequence_length, self.input_dim)
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        torch.onnx.export(
            self.model,
            dummy_input,
            path,
            input_names=['input'],
            output_names=['output'],
            dynamic_axes={
                'input': {0: 'batch_size'},
                'output': {0: 'batch_size'}
            }
        )
        self.logger.info(f"Model exported to ONNX: {path}")


def create_detector(config: Optional[Any] = None) -> IDSDetector:
    """
    工厂函数：根据配置创建IDSDetector实例
    
    Args:
        config: 配置对象（可选）
    
    Returns:
        IDSDetector实例
    """
    if config:
        return IDSDetector(
            model_path=config.model.model_path,
            input_dim=config.model.input_dim,
            num_classes=config.model.num_classes,
            sequence_length=config.inference.sequence_length,
            num_channels=config.model.num_channels,
            kernel_size=config.model.kernel_size,
            dropout=config.model.dropout,
            confidence_threshold=config.inference.confidence_threshold,
            alert_threshold=config.inference.alert_threshold
        )
    return IDSDetector()
