import torch
import torch.nn as nn
from typing import List, Optional

from ..utils.logger import LoggerMixin


class Chomp1d(nn.Module):
    """
    1D裁剪层
    
    用于裁剪卷积输出的填充部分，保持因果性
    """
    
    def __init__(self, chomp_size: int):
        """
        Args:
            chomp_size: 裁剪大小
        """
        super().__init__()
        self.chomp_size = chomp_size
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        前向传播
        
        Args:
            x: 输入张量 (batch, channels, length)
        
        Returns:
            裁剪后的张量
        """
        return x[:, :, :-self.chomp_size].contiguous()
    
    def extra_repr(self) -> str:
        return f'chomp_size={self.chomp_size}'


class TemporalBlock(nn.Module):
    """
    时序卷积块
    
    包含两个扩张卷积层，带有残差连接
    """
    
    def __init__(
        self,
        n_inputs: int,
        n_outputs: int,
        kernel_size: int,
        stride: int,
        dilation: int,
        padding: int,
        dropout: float = 0.2
    ):
        """
        Args:
            n_inputs: 输入通道数
            n_outputs: 输出通道数
            kernel_size: 卷积核大小
            stride: 步幅
            dilation: 扩张率
            padding: 填充大小
            dropout: Dropout概率
        """
        super().__init__()
        
        # 第一个卷积层
        self.conv1 = nn.Conv1d(
            n_inputs, n_outputs, kernel_size,
            stride=stride, padding=padding, dilation=dilation
        )
        self.chomp1 = Chomp1d(padding)
        self.relu1 = nn.ReLU()
        self.dropout1 = nn.Dropout(dropout)
        
        # 第二个卷积层
        self.conv2 = nn.Conv1d(
            n_outputs, n_outputs, kernel_size,
            stride=stride, padding=padding, dilation=dilation
        )
        self.chomp2 = Chomp1d(padding)
        self.relu2 = nn.ReLU()
        self.dropout2 = nn.Dropout(dropout)
        
        # 顺序容器
        self.net = nn.Sequential(
            self.conv1, self.chomp1, self.relu1, self.dropout1,
            self.conv2, self.chomp2, self.relu2, self.dropout2
        )
        
        # 下采样层（当输入输出通道数不同时）
        self.downsample = nn.Conv1d(n_inputs, n_outputs, 1) if n_inputs != n_outputs else None
        self.relu = nn.ReLU()
        
        # 初始化权重
        self._init_weights()
    
    def _init_weights(self):
        """初始化网络权重"""
        for m in self.modules():
            if isinstance(m, nn.Conv1d):
                nn.init.kaiming_normal_(m.weight, mode='fan_in', nonlinearity='relu')
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        前向传播
        
        Args:
            x: 输入张量 (batch, channels, length)
        
        Returns:
            输出张量
        """
        out = self.net(x)
        res = x if self.downsample is None else self.downsample(x)
        return self.relu(out + res)
    
    def extra_repr(self) -> str:
        return f'channels={self.conv1.in_channels}->{self.conv1.out_channels}'


class TCN(nn.Module, LoggerMixin):
    """
    时序卷积网络（TCN）
    
    用于网络入侵检测的时序特征学习
    """
    
    def __init__(
        self,
        input_dim: int = 39,
        num_classes: int = 2,
        num_channels: Optional[List[int]] = None,
        kernel_size: int = 3,
        dropout: float = 0.2
    ):
        """
        Args:
            input_dim: 输入特征维度
            num_classes: 输出类别数
            num_channels: 各层通道数列表
            kernel_size: 卷积核大小
            dropout: Dropout概率
        """
        super().__init__()
        LoggerMixin.__init__(self)
        
        # 默认通道配置
        if num_channels is None:
            num_channels = [128, 256]
        
        self.input_dim = input_dim
        self.num_classes = num_classes
        self.num_channels = num_channels
        self.kernel_size = kernel_size
        self.dropout = dropout
        
        # 构建TCN层
        layers = []
        num_levels = len(num_channels)
        
        for i in range(num_levels):
            in_channels = input_dim if i == 0 else num_channels[i - 1]
            out_channels = num_channels[i]
            dilation = 2 ** i  # 指数增长的扩张率
            padding = (kernel_size - 1) * dilation
            
            layers.append(TemporalBlock(
                in_channels, out_channels, kernel_size,
                stride=1, dilation=dilation, padding=padding, dropout=dropout
            ))
        
        self.network = nn.Sequential(*layers)
        
        # 全局平均池化
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        
        # 分类器
        self.classifier = nn.Linear(num_channels[-1], num_classes)
        
        # 计算参数量
        self.num_params = sum(p.numel() for p in self.parameters())
        self.logger.info(f"TCN initialized: {self.num_params / 1e6:.2f}M parameters")
        self.logger.info(f"  Architecture: {num_channels}")
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        前向传播
        
        Args:
            x: 输入张量 (batch, seq_len, input_dim)
        
        Returns:
            输出logits (batch, num_classes)
        """
        # 转置为 (batch, input_dim, seq_len)
        x = x.transpose(1, 2)
        
        # TCN特征提取
        features = self.network(x)
        
        # 全局池化
        pooled = self.global_pool(features).squeeze(-1)
        
        # 分类
        logits = self.classifier(pooled)
        
        return logits
    
    def get_representations(self, x: torch.Tensor) -> torch.Tensor:
        """
        获取特征表示（用于可视化或迁移学习）
        
        Args:
            x: 输入张量 (batch, seq_len, input_dim)
        
        Returns:
            特征表示 (batch, num_channels[-1])
        """
        x = x.transpose(1, 2)
        features = self.network(x)
        pooled = self.global_pool(features).squeeze(-1)
        return pooled
    
    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """
        预测概率
        
        Args:
            x: 输入张量
        
        Returns:
            概率分布
        """
        with torch.no_grad():
            logits = self.forward(x)
            probs = torch.softmax(logits, dim=1)
        return probs
    
    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """
        预测类别
        
        Args:
            x: 输入张量
        
        Returns:
            预测类别索引
        """
        probs = self.predict_proba(x)
        return torch.argmax(probs, dim=1)
    
    def get_model_info(self) -> dict:
        """
        获取模型信息
        
        Returns:
            模型信息字典
        """
        return {
            'input_dim': self.input_dim,
            'num_classes': self.num_classes,
            'num_channels': self.num_channels,
            'kernel_size': self.kernel_size,
            'dropout': self.dropout,
            'num_parameters': self.num_params,
            'model_size_mb': self.num_params * 4 / (1024 * 1024),
        }


def create_tcn_model(
    input_dim: int = 39,
    num_classes: int = 2,
    num_channels: Optional[List[int]] = None,
    kernel_size: int = 3,
    dropout: float = 0.2
) -> TCN:
    """
    工厂函数：创建TCN模型
    
    Args:
        input_dim: 输入特征维度
        num_classes: 输出类别数
        num_channels: 各层通道数列表
        kernel_size: 卷积核大小
        dropout: Dropout概率
    
    Returns:
        TCN模型实例
    """
    return TCN(
        input_dim=input_dim,
        num_classes=num_classes,
        num_channels=num_channels,
        kernel_size=kernel_size,
        dropout=dropout
    )
