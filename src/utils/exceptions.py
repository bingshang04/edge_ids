class EdgeIDSException(Exception):
    """Edge-IDS基础异常类"""
    
    def __init__(self, message: str = "", error_code: int = 500, details: dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
    
    def __str__(self) -> str:
        if self.details:
            return f"[{self.error_code}] {self.message} - Details: {self.details}"
        return f"[{self.error_code}] {self.message}"


class ConfigError(EdgeIDSException):
    """配置错误"""
    
    def __init__(self, message: str = "Configuration error", details: dict = None):
        super().__init__(message, error_code=400, details=details)


class ModelError(EdgeIDSException):
    """模型相关错误"""
    
    def __init__(self, message: str = "Model error", details: dict = None):
        super().__init__(message, error_code=500, details=details)


class ModelNotFoundError(ModelError):
    """模型文件不存在"""
    
    def __init__(self, model_path: str):
        super().__init__(
            message=f"Model file not found: {model_path}",
            details={'model_path': model_path}
        )


class ModelLoadError(ModelError):
    """模型加载失败"""
    
    def __init__(self, model_path: str, reason: str):
        super().__init__(
            message=f"Failed to load model from {model_path}: {reason}",
            details={'model_path': model_path, 'reason': reason}
        )


class CaptureError(EdgeIDSException):
    """数据包捕获错误"""
    
    def __init__(self, message: str = "Packet capture error", details: dict = None):
        super().__init__(message, error_code=500, details=details)


class InterfaceNotFoundError(CaptureError):
    """网络接口不存在"""
    
    def __init__(self, interface: str):
        super().__init__(
            message=f"Network interface not found: {interface}",
            details={'interface': interface}
        )


class PermissionError(CaptureError):
    """权限不足（捕获需要root权限）"""
    
    def __init__(self, interface: str):
        super().__init__(
            message=f"Permission denied for interface {interface}. Run with sudo.",
            details={'interface': interface}
        )


class ScapyNotAvailableError(CaptureError):
    """Scapy库不可用"""
    
    def __init__(self):
        super().__init__(
            message="Scapy library is not available. Install with: pip install scapy",
            details={'install_command': 'pip install scapy'}
        )


class FeatureError(EdgeIDSException):
    """特征提取错误"""
    
    def __init__(self, message: str = "Feature extraction error", details: dict = None):
        super().__init__(message, error_code=500, details=details)


class InvalidFeatureDimensionError(FeatureError):
    """特征维度不匹配"""
    
    def __init__(self, expected: int, actual: int):
        super().__init__(
            message=f"Feature dimension mismatch: expected {expected}, got {actual}",
            details={'expected': expected, 'actual': actual}
        )


class InferenceError(EdgeIDSException):
    """推理错误"""
    
    def __init__(self, message: str = "Inference error", details: dict = None):
        super().__init__(message, error_code=500, details=details)


class PreprocessingError(InferenceError):
    """数据预处理错误"""
    
    def __init__(self, message: str = "Data preprocessing error", details: dict = None):
        super().__init__(message, details=details)


class WebServerError(EdgeIDSException):
    """Web服务器错误"""
    
    def __init__(self, message: str = "Web server error", details: dict = None):
        super().__init__(message, error_code=500, details=details)


class ValidationError(EdgeIDSException):
    """数据验证错误"""
    
    def __init__(self, message: str = "Validation error", details: dict = None):
        super().__init__(message, error_code=400, details=details)
