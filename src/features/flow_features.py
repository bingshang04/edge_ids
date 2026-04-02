import time
import numpy as np
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple, Any
from enum import Enum

from ..utils.logger import LoggerMixin
from ..utils.exceptions import FeatureError, InvalidFeatureDimensionError
from ..utils.helpers import safe_divide, get_flow_id
from ..capture.packet_capture import PacketInfo


class FlowFeature(Enum):
    """特征索引枚举（用于清晰标识每个特征）"""
    # 基础计数特征 (0-5)
    FWD_PKT_COUNT = 0
    BWD_PKT_COUNT = 1
    TOTAL_PKT_COUNT = 2
    FWD_BYTES = 3
    BWD_BYTES = 4
    TOTAL_BYTES = 5
    
    # 速率特征 (6-9)
    PKT_RATE = 6
    BYTE_RATE = 7
    FWD_AVG_PKT_SIZE = 8
    BWD_AVG_PKT_SIZE = 9
    
    # 正向包长度统计 (10-13)
    FWD_PKT_LEN_MIN = 10
    FWD_PKT_LEN_MAX = 11
    FWD_PKT_LEN_MEAN = 12
    FWD_PKT_LEN_STD = 13
    
    # 反向包长度统计 (14-17)
    BWD_PKT_LEN_MIN = 14
    BWD_PKT_LEN_MAX = 15
    BWD_PKT_LEN_MEAN = 16
    BWD_PKT_LEN_STD = 17
    
    # IAT统计 (18-25)
    FWD_IAT_MIN = 18
    FWD_IAT_MAX = 19
    FWD_IAT_MEAN = 20
    FWD_IAT_STD = 21
    BWD_IAT_MIN = 22
    BWD_IAT_MAX = 23
    BWD_IAT_MEAN = 24
    BWD_IAT_STD = 25
    
    # TCP标志统计 (26-31)
    FIN_COUNT = 26
    SYN_COUNT = 27
    RST_COUNT = 28
    PSH_COUNT = 29
    ACK_COUNT = 30
    URG_COUNT = 31
    
    # 头部字节统计 (32-35)
    FWD_HEADER_BYTES = 32
    BWD_HEADER_BYTES = 33
    FWD_HEADER_BYTES_AVG = 34
    BWD_HEADER_BYTES_AVG = 35
    
    # 比例特征 (36-38)
    FWD_PKT_RATIO = 36
    FWD_BYTES_RATIO = 37
    SYN_RATIO = 38


@dataclass
class FlowStats:
    """
    单条流的统计信息
    
    维护流的完整统计信息，用于特征提取
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_time: float
    
    # 基础计数
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    
    # 历史记录（用于计算统计特征）
    packet_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    packet_lengths: deque = field(default_factory=lambda: deque(maxlen=1000))
    fwd_packet_times: deque = field(default_factory=lambda: deque(maxlen=500))
    bwd_packet_times: deque = field(default_factory=lambda: deque(maxlen=500))
    fwd_packet_lengths: deque = field(default_factory=lambda: deque(maxlen=500))
    bwd_packet_lengths: deque = field(default_factory=lambda: deque(maxlen=500))
    
    # IAT列表
    fwd_iat_list: deque = field(default_factory=lambda: deque(maxlen=100))
    bwd_iat_list: deque = field(default_factory=lambda: deque(maxlen=100))
    
    # TCP标志统计
    fin_flags: int = 0
    syn_flags: int = 0
    rst_flags: int = 0
    psh_flags: int = 0
    ack_flags: int = 0
    urg_flags: int = 0
    
    # 头部字节统计
    fwd_header_bytes: int = 0
    bwd_header_bytes: int = 0
    
    def update(self, packet_info: PacketInfo) -> None:
        """
        使用数据包信息更新流统计
        
        Args:
            packet_info: 数据包信息
        """
        timestamp = packet_info.timestamp
        length = packet_info.length
        direction = packet_info.direction
        flags = packet_info.flags
        
        # 更新时间
        self.last_time = timestamp
        self.packet_times.append(timestamp)
        self.packet_lengths.append(length)
        
        # 根据方向更新统计
        if direction == "fwd":
            # 计算IAT
            if self.fwd_packet_times:
                iat = timestamp - self.fwd_packet_times[-1]
                self.fwd_iat_list.append(iat)
            
            self.fwd_packets += 1
            self.fwd_bytes += length
            self.fwd_packet_times.append(timestamp)
            self.fwd_packet_lengths.append(length)
            # 估算头部字节（TCP/IP头部约40字节，UDP约28字节）
            header_len = 40 if self.protocol == "TCP" else 28
            self.fwd_header_bytes += header_len
        else:
            # 计算IAT
            if self.bwd_packet_times:
                iat = timestamp - self.bwd_packet_times[-1]
                self.bwd_iat_list.append(iat)
            
            self.bwd_packets += 1
            self.bwd_bytes += length
            self.bwd_packet_times.append(timestamp)
            self.bwd_packet_lengths.append(length)
            header_len = 40 if self.protocol == "TCP" else 28
            self.bwd_header_bytes += header_len
        
        # 统计TCP标志
        if 'F' in flags:
            self.fin_flags += 1
        if 'S' in flags:
            self.syn_flags += 1
        if 'R' in flags:
            self.rst_flags += 1
        if 'P' in flags:
            self.psh_flags += 1
        if 'A' in flags:
            self.ack_flags += 1
        if 'U' in flags:
            self.urg_flags += 1
    
    @property
    def duration(self) -> float:
        """流持续时间"""
        return max(self.last_time - self.start_time, 0.0001)
    
    @property
    def total_packets(self) -> int:
        """总包数"""
        return self.fwd_packets + self.bwd_packets
    
    @property
    def total_bytes(self) -> int:
        """总字节数"""
        return self.fwd_bytes + self.bwd_bytes
    
    def is_expired(self, current_time: float, timeout: float) -> bool:
        """
        检查流是否已超时
        
        Args:
            current_time: 当前时间
            timeout: 超时时间
        
        Returns:
            是否已超时
        """
        return (current_time - self.last_time) > timeout
    
    def is_finished(self) -> bool:
        """
        检查流是否已结束（收到FIN或RST）
        
        Returns:
            是否已结束
        """
        return self.fin_flags > 0 or self.rst_flags > 0


class FeatureExtractor(LoggerMixin):
    """
    UNSW-NB15对齐的39维特征提取器
    
    从网络流中提取39维统计特征，用于入侵检测模型输入
    """
    
    FEATURE_DIM = 39  # 特征维度常量
    
    def __init__(
        self,
        flow_timeout: float = 120.0,
        max_flows: int = 10000,
        cleanup_interval: float = 10.0
    ):
        """
        初始化特征提取器
        
        Args:
            flow_timeout: 流超时时间（秒）
            max_flows: 最大活跃流数
            cleanup_interval: 清理间隔（秒）
        """
        super().__init__()
        
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.cleanup_interval = cleanup_interval
        
        # 活跃流字典
        self._flows: Dict[str, FlowStats] = {}
        
        # 上次清理时间
        self._last_cleanup = time.time()
        
        # 统计信息
        self._stats = {
            'flows_created': 0,
            'flows_completed': 0,
            'flows_expired': 0,
            'packets_processed': 0,
        }
        
        self.logger.debug(
            f"FeatureExtractor initialized: timeout={flow_timeout}s, "
            f"max_flows={max_flows}"
        )
    
    @property
    def active_flow_count(self) -> int:
        """当前活跃流数量"""
        return len(self._flows)
    
    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self._stats.copy()
    
    def _get_or_create_flow(self, packet_info: PacketInfo) -> FlowStats:
        """
        获取或创建流
        
        Args:
            packet_info: 数据包信息
        
        Returns:
            FlowStats对象
        """
        flow_id = packet_info.flow_id
        
        if flow_id not in self._flows:
            # 检查是否达到最大流数限制
            if len(self._flows) >= self.max_flows:
                self.logger.warning(f"Max flows reached ({self.max_flows}), removing oldest flow")
                # 移除最老的流
                oldest_id = min(self._flows.keys(), key=lambda k: self._flows[k].last_time)
                del self._flows[oldest_id]
            
            # 创建新流
            self._flows[flow_id] = FlowStats(
                flow_id=flow_id,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port,
                protocol=packet_info.protocol,
                start_time=packet_info.timestamp,
                last_time=packet_info.timestamp
            )
            self._stats['flows_created'] += 1
        
        return self._flows[flow_id]
    
    def _cleanup_expired_flows(self, current_time: float) -> int:
        """
        清理超时的流
        
        Args:
            current_time: 当前时间
        
        Returns:
            清理的流数量
        """
        expired = [
            fid for fid, flow in self._flows.items()
            if flow.is_expired(current_time, self.flow_timeout)
        ]
        
        for fid in expired:
            del self._flows[fid]
        
        if expired:
            self._stats['flows_expired'] += len(expired)
            self.logger.debug(f"Cleaned up {len(expired)} expired flows")
        
        self._last_cleanup = current_time
        return len(expired)
    
    def _calculate_stats(self, data: List[float]) -> Tuple[float, float, float, float]:
        """
        计算统计量（min, max, mean, std）
        
        Args:
            data: 数据列表
        
        Returns:
            (最小值, 最大值, 均值, 标准差)
        """
        if not data:
            return 0.0, 0.0, 0.0, 0.0
        
        arr = np.array(data, dtype=np.float32)
        min_val = float(np.min(arr))
        max_val = float(np.max(arr))
        mean_val = float(np.mean(arr))
        std_val = float(np.std(arr)) if len(arr) > 1 else 0.0
        
        return min_val, max_val, mean_val, std_val
    
    def _extract_features(self, flow: FlowStats) -> np.ndarray:
        """
        提取39维特征向量
        
        Args:
            flow: 流统计信息
        
        Returns:
            39维特征数组
        """
        features = []
        duration = flow.duration
        total_packets = flow.total_packets
        total_bytes = flow.total_bytes
        
        # 基础计数特征 (6维)
        features.extend([
            float(flow.fwd_packets),
            float(flow.bwd_packets),
            float(total_packets),
            float(flow.fwd_bytes),
            float(flow.bwd_bytes),
            float(total_bytes),
        ])
        
        # 速率特征 (4维)
        features.extend([
            safe_divide(total_packets, duration),
            safe_divide(total_bytes, duration),
            safe_divide(flow.fwd_bytes, flow.fwd_packets),
            safe_divide(flow.bwd_bytes, flow.bwd_packets),
        ])
        
        # 包长度统计 (8维)
        fwd_lengths = list(flow.fwd_packet_lengths)
        bwd_lengths = list(flow.bwd_packet_lengths)
        features.extend(self._calculate_stats(fwd_lengths))
        features.extend(self._calculate_stats(bwd_lengths))
        
        # IAT统计 (8维)
        fwd_iats = list(flow.fwd_iat_list)
        bwd_iats = list(flow.bwd_iat_list)
        features.extend(self._calculate_stats(fwd_iats))
        features.extend(self._calculate_stats(bwd_iats))
        
        # TCP标志统计 (6维)
        features.extend([
            float(flow.fin_flags),
            float(flow.syn_flags),
            float(flow.rst_flags),
            float(flow.psh_flags),
            float(flow.ack_flags),
            float(flow.urg_flags),
        ])
        
        # 头部字节统计 (4维)
        features.extend([
            float(flow.fwd_header_bytes),
            float(flow.bwd_header_bytes),
            safe_divide(flow.fwd_header_bytes, flow.fwd_packets),
            safe_divide(flow.bwd_header_bytes, flow.bwd_packets),
        ])
        
        # 比例特征 (3维)
        features.extend([
            safe_divide(flow.fwd_packets, total_packets),
            safe_divide(flow.fwd_bytes, total_bytes),
            safe_divide(flow.syn_flags, total_packets),
        ])
        
        # 验证特征维度
        if len(features) != self.FEATURE_DIM:
            raise InvalidFeatureDimensionError(self.FEATURE_DIM, len(features))
        
        return np.array(features, dtype=np.float32)
    
    def process_packet(self, packet_info: PacketInfo) -> Optional[np.ndarray]:
        """
        处理单个数据包，返回特征向量（当流完成或超时时）
        
        Args:
            packet_info: 数据包信息
        
        Returns:
            特征数组（流完成时）或None
        """
        current_time = time.time()
        
        # 定期清理过期流
        if current_time - self._last_cleanup > self.cleanup_interval:
            self._cleanup_expired_flows(current_time)
        
        # 获取或创建流
        flow = self._get_or_create_flow(packet_info)
        
        # 更新流统计
        flow.update(packet_info)
        self._stats['packets_processed'] += 1
        
        # 检查流是否结束
        is_finished = flow.is_finished()
        
        if is_finished:
            features = self._extract_features(flow)
            del self._flows[packet_info.flow_id]
            self._stats['flows_completed'] += 1
            return features
        
        return None
    
    def force_extract(self, flow_id: Optional[str] = None) -> List[np.ndarray]:
        """
        强制提取特征（用于程序退出时提取所有活跃流的特征）
        
        Args:
            flow_id: 指定流ID（None表示所有流）
        
        Returns:
            特征数组列表
        """
        features_list = []
        
        if flow_id:
            if flow_id in self._flows:
                features_list.append(self._extract_features(self._flows[flow_id]))
                del self._flows[flow_id]
        else:
            for flow in list(self._flows.values()):
                features_list.append(self._extract_features(flow))
            self._flows.clear()
        
        return features_list
    
    def get_flow_info(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """
        获取流信息
        
        Args:
            flow_id: 流ID
        
        Returns:
            流信息字典或None
        """
        flow = self._flows.get(flow_id)
        if flow:
            return {
                'flow_id': flow.flow_id,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'src_port': flow.src_port,
                'dst_port': flow.dst_port,
                'protocol': flow.protocol,
                'duration': flow.duration,
                'total_packets': flow.total_packets,
                'total_bytes': flow.total_bytes,
            }
        return None
    
    def get_all_flows_info(self) -> List[Dict[str, Any]]:
        """获取所有活跃流的信息"""
        return [self.get_flow_info(fid) for fid in self._flows.keys()]
    
    def clear(self) -> int:
        """
        清空所有流
        
        Returns:
            清空的流数量
        """
        count = len(self._flows)
        self._flows.clear()
        return count


def create_feature_extractor(config: Optional[Any] = None) -> FeatureExtractor:
    """
    工厂函数：根据配置创建FeatureExtractor实例
    
    Args:
        config: 配置对象（可选）
    
    Returns:
        FeatureExtractor实例
    """
    if config:
        return FeatureExtractor(
            flow_timeout=config.feature.flow_timeout,
            max_flows=config.feature.max_flows
        )
    return FeatureExtractor()
