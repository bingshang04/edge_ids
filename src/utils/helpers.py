import os
import re
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Union, Tuple, Optional


def ensure_dir(path: Union[str, Path]) -> Path:
    """
    确保目录存在，如果不存在则创建
    
    Args:
        path: 目录路径
    
    Returns:
        Path对象
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_timestamp(fmt: str = "%Y%m%d_%H%M%S") -> str:
    """
    获取当前时间戳字符串
    
    Args:
        fmt: 时间格式字符串
    
    Returns:
        格式化的时间字符串
    """
    return datetime.now().strftime(fmt)


def format_bytes(size_bytes: Union[int, float]) -> str:
    """
    将字节数格式化为人类可读的字符串
    
    Args:
        size_bytes: 字节数
    
    Returns:
        格式化后的字符串（如：1.5 MB）
    """
    if size_bytes == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"


def format_duration(seconds: Union[int, float]) -> str:
    """
    将秒数格式化为人类可读的持续时间字符串
    
    Args:
        seconds: 秒数
    
    Returns:
        格式化后的字符串（如：2h 30m 15s）
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours}h {minutes}m {secs}s"


def validate_ip_address(ip: str) -> Tuple[bool, Optional[str]]:
    """
    验证IP地址是否有效
    
    Args:
        ip: IP地址字符串
    
    Returns:
        (是否有效, 错误信息)
    """
    try:
        ipaddress.ip_address(ip)
        return True, None
    except ValueError as e:
        return False, str(e)


def get_flow_id(
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    protocol: str
) -> Tuple[str, str]:
    """
    生成双向流ID和方向
    
    Args:
        src_ip: 源IP地址
        dst_ip: 目的IP地址
        src_port: 源端口
        dst_port: 目的端口
        protocol: 协议类型
    
    Returns:
        (流ID, 方向) 方向为 'fwd' 或 'bwd'
    """
    # 统一方向：较小的端点在前
    if (src_ip, src_port) < (dst_ip, dst_port):
        flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        direction = "fwd"
    else:
        flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
        direction = "bwd"
    
    return flow_id, direction


def parse_packet_flags(flags_str: str) -> dict:
    """
    解析TCP标志位字符串
    
    Args:
        flags_str: 标志位字符串（如 'SA'）
    
    Returns:
        标志位字典
    """
    flag_map = {
        'F': 'fin',
        'S': 'syn',
        'R': 'rst',
        'P': 'psh',
        'A': 'ack',
        'U': 'urg',
        'E': 'ece',
        'C': 'cwr'
    }
    
    result = {name: False for name in flag_map.values()}
    
    for char in flags_str:
        if char in flag_map:
            result[flag_map[char]] = True
    
    return result


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    安全的除法运算，避免除以零
    
    Args:
        numerator: 分子
        denominator: 分母
        default: 除零时的默认值
    
    Returns:
        除法结果或默认值
    """
    if denominator == 0:
        return default
    return numerator / denominator


def clamp(value: float, min_val: float, max_val: float) -> float:
    """
    将值限制在指定范围内
    
    Args:
        value: 输入值
        min_val: 最小值
        max_val: 最大值
    
    Returns:
        限制后的值
    """
    return max(min_val, min(max_val, value))


def moving_average(data: list, window_size: int) -> list:
    """
    计算移动平均
    
    Args:
        data: 数据列表
        window_size: 窗口大小
    
    Returns:
        移动平均列表
    """
    if not data or window_size <= 0:
        return []
    
    result = []
    for i in range(len(data)):
        start = max(0, i - window_size + 1)
        window = data[start:i + 1]
        result.append(sum(window) / len(window))
    
    return result


def calculate_percentile(data: list, percentile: float) -> float:
    """
    计算百分位数
    
    Args:
        data: 数据列表
        percentile: 百分位（0-100）
    
    Returns:
        百分位数值
    """
    if not data:
        return 0.0
    
    sorted_data = sorted(data)
    index = (percentile / 100) * (len(sorted_data) - 1)
    lower = int(index)
    upper = min(lower + 1, len(sorted_data) - 1)
    weight = index - lower
    
    return sorted_data[lower] * (1 - weight) + sorted_data[upper] * weight


def truncate_string(s: str, max_length: int, suffix: str = "...") -> str:
    """
    截断字符串到指定长度
    
    Args:
        s: 原始字符串
        max_length: 最大长度
        suffix: 截断后缀
    
    Returns:
        截断后的字符串
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def sanitize_filename(filename: str) -> str:
    """
    清理文件名，移除非法字符
    
    Args:
        filename: 原始文件名
    
    Returns:
        清理后的文件名
    """
    # 移除非法字符
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # 移除控制字符
    sanitized = re.sub(r'[\x00-\x1f\x7f]', '', sanitized)
    # 限制长度
    return sanitized[:255]
