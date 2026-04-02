import os
import sys
import platform
import psutil
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

from .logger import LoggerMixin


class PlatformType(str, Enum):
    """平台类型枚举"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    RASPBERRY_PI = "raspberry_pi"
    UNKNOWN = "unknown"


@dataclass
class SystemInfo:
    """系统信息数据类"""
    platform_type: PlatformType
    os_name: str
    machine: str
    processor: str
    system: str
    python_version: str
    cpu_count: int
    memory_gb: float
    is_64bit: bool


class PlatformDetector(LoggerMixin):
    """平台检测器"""
    
    # 树莓派硬件标识
    RPI_IDENTIFIERS = ['arm', 'aarch64', 'armv7l', 'armv6l']
    
    # x86硬件标识
    X86_IDENTIFIERS = ['x86_64', 'amd64', 'i386', 'i686', 'AMD64', 'x86']
    
    def __init__(self):
        super().__init__()
        self._platform_type: Optional[PlatformType] = None
        self._system_info: Optional[SystemInfo] = None
        self._is_windows = sys.platform.startswith('win')
        self._is_linux = sys.platform.startswith('linux')
        self._is_macos = sys.platform.startswith('darwin')
    
    def detect(self) -> PlatformType:
        """
        检测运行平台
        
        Returns:
            平台类型
        """
        machine = platform.machine().lower()
        
        # 首先检测操作系统
        if self._is_windows:
            self._platform_type = PlatformType.WINDOWS
        elif self._is_macos:
            self._platform_type = PlatformType.MACOS
        elif self._is_linux:
            # Linux系统下进一步检测是否是树莓派
            if any(ident in machine for ident in self.RPI_IDENTIFIERS):
                self._platform_type = PlatformType.RASPBERRY_PI
            else:
                self._platform_type = PlatformType.LINUX
        else:
            self._platform_type = PlatformType.UNKNOWN
            self.logger.warning(f"Unknown platform: {sys.platform}, machine: {machine}")
        
        self.logger.info(f"Detected platform: {self._platform_type.value}")
        return self._platform_type
    
    def get_system_info(self) -> SystemInfo:
        """
        获取系统信息
        
        Returns:
            系统信息
        """
        if self._system_info is None:
            mem = psutil.virtual_memory()
            self._system_info = SystemInfo(
                platform_type=self.detect(),
                os_name=sys.platform,
                machine=platform.machine(),
                processor=platform.processor() or "Unknown",
                system=f"{platform.system()} {platform.release()}",
                python_version=platform.python_version(),
                cpu_count=psutil.cpu_count(),
                memory_gb=mem.total / (1024 ** 3),
                is_64bit=sys.maxsize > 2 ** 32
            )
        return self._system_info
    
    def is_windows(self) -> bool:
        """是否在Windows上运行"""
        return self._is_windows
    
    def is_linux(self) -> bool:
        """是否在Linux上运行"""
        return self._is_linux
    
    def is_macos(self) -> bool:
        """是否在macOS上运行"""
        return self._is_macos
    
    def is_raspberry_pi(self) -> bool:
        """是否在树莓派上运行"""
        return self.detect() == PlatformType.RASPBERRY_PI


class NetworkInterfaceDetector(LoggerMixin):
    """网络接口检测器"""
    
    def __init__(self):
        super().__init__()
    
    def get_all_interfaces(self) -> List[Dict[str, Any]]:
        """
        获取所有网络接口
        
        Returns:
            接口信息列表
        """
        interfaces = []
        
        try:
            # 使用psutil获取网络接口
            stats = psutil.net_if_stats()
            addresses = psutil.net_if_addrs()
            
            for name, stat in stats.items():
                # 跳过回环接口
                if name.startswith('lo') or name.startswith('Loopback'):
                    continue
                
                # 获取IP地址
                ip_list = []
                if name in addresses:
                    for addr in addresses[name]:
                        if addr.family == 2:  # AF_INET (IPv4)
                            ip_list.append(addr.address)
                
                interfaces.append({
                    'name': name,
                    'is_up': stat.isup,
                    'speed_mbps': stat.speed if stat.speed > 0 else 'Unknown',
                    'mtu': stat.mtu,
                    'ip_addresses': ip_list
                })
        except Exception as e:
            self.logger.warning(f"Failed to get network interfaces: {e}")
        
        return interfaces
    
    def get_default_interface(self) -> Optional[str]:
        """
        获取默认网络接口
        
        Returns:
            接口名称或None
        """
        interfaces = self.get_all_interfaces()
        
        if not interfaces:
            return None
        
        # Windows常见接口名
        windows_defaults = ['Ethernet', 'Wi-Fi', 'WLAN', '以太网', '无线网络连接']
        # Linux常见接口名
        linux_defaults = ['eth0', 'ens33', 'ens160', 'enp0s3', 'wlan0', 'wlp2s0']
        
        detector = PlatformDetector()
        
        # 根据平台选择默认接口
        if detector.is_windows():
            defaults = windows_defaults
        elif detector.is_linux():
            defaults = linux_defaults
        else:
            defaults = linux_defaults
        
        # 查找匹配的接口
        for default in defaults:
            for iface in interfaces:
                if default.lower() in iface['name'].lower() and iface['is_up']:
                    return iface['name']
        
        # 返回第一个可用的接口
        for iface in interfaces:
            if iface['is_up']:
                return iface['name']
        
        return interfaces[0]['name'] if interfaces else None
    
    def list_interfaces(self) -> None:
        """列出所有可用的网络接口"""
        interfaces = self.get_all_interfaces()
        
        print("=" * 60)
        print("可用的网络接口:")
        print("=" * 60)
        
        for i, iface in enumerate(interfaces, 1):
            status = "已连接" if iface['is_up'] else "未连接"
            print(f"{i}. {iface['name']}")
            print(f"   状态: {status}")
            print(f"   IP: {', '.join(iface['ip_addresses']) if iface['ip_addresses'] else '无'}")
            print(f"   速度: {iface['speed_mbps']} Mbps" if iface['speed_mbps'] != 'Unknown' else "   速度: 未知")
            print()
        
        default = self.get_default_interface()
        if default:
            print(f"推荐接口: {default}")
        print("=" * 60)


class PlatformAdapter(LoggerMixin):
    """
    平台适配器
    
    根据平台类型提供优化配置
    """
    
    # 平台默认配置
    DEFAULT_CONFIGS: Dict[PlatformType, Dict[str, Any]] = {
        PlatformType.WINDOWS: {
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
            'capture_queue_size': 10000,
            'max_flows': 10000,
            'needs_admin': True,  # Windows需要管理员权限
        },
        PlatformType.LINUX: {
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
            'capture_queue_size': 10000,
            'max_flows': 10000,
            'needs_admin': True,  # Linux需要root权限
        },
        PlatformType.MACOS: {
            'batch_size': 32,
            'sequence_length': 15,
            'hidden_dim': 64,
            'num_layers': 2,
            'use_tflite': False,
            'quantization': 'FP32',
            'max_memory_mb': 4096,
            'inference_threads': 4,
            'learning_rate': 0.001,
            'kernel_size': 3,
            'dropout': 0.2,
            'capture_queue_size': 5000,
            'max_flows': 5000,
            'needs_admin': True,
        },
        PlatformType.RASPBERRY_PI: {
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
            'capture_queue_size': 5000,
            'max_flows': 5000,
            'needs_admin': True,
        },
        PlatformType.UNKNOWN: {
            'batch_size': 32,
            'sequence_length': 15,
            'hidden_dim': 64,
            'num_layers': 2,
            'use_tflite': False,
            'quantization': 'FP32',
            'max_memory_mb': 4096,
            'inference_threads': 4,
            'learning_rate': 0.001,
            'kernel_size': 3,
            'dropout': 0.2,
            'capture_queue_size': 5000,
            'max_flows': 5000,
            'needs_admin': True,
        }
    }
    
    def __init__(self):
        super().__init__()
        self._detector = PlatformDetector()
        self._config: Optional[Dict[str, Any]] = None
    
    def get_config(self) -> Dict[str, Any]:
        """
        获取平台优化配置
        
        Returns:
            配置字典
        """
        if self._config is None:
            platform_type = self._detector.detect()
            base_config = self.DEFAULT_CONFIGS.get(platform_type, self.DEFAULT_CONFIGS[PlatformType.UNKNOWN])
            
            # 根据实际硬件调整配置
            self._config = self._adjust_config(base_config)
            
            self.logger.info(f"Platform config loaded for {platform_type.value}")
        
        return self._config.copy()
    
    def _adjust_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据实际硬件调整配置
        
        Args:
            config: 基础配置
        
        Returns:
            调整后的配置
        """
        adjusted = config.copy()
        
        # 获取系统信息
        sys_info = self._detector.get_system_info()
        
        # 根据内存调整
        if sys_info.memory_gb < 2:
            adjusted['batch_size'] = min(adjusted['batch_size'], 8)
            adjusted['max_flows'] = min(adjusted['max_flows'], 3000)
            adjusted['capture_queue_size'] = min(adjusted['capture_queue_size'], 3000)
        elif sys_info.memory_gb > 16:
            adjusted['batch_size'] = max(adjusted['batch_size'], 128)
        
        # 根据CPU核心数调整线程数
        if sys_info.cpu_count:
            adjusted['inference_threads'] = min(adjusted['inference_threads'], sys_info.cpu_count)
        
        return adjusted
    
    def get_optimal_num_workers(self) -> int:
        """
        获取最优工作线程数
        
        Returns:
            线程数
        """
        cpu_count = psutil.cpu_count()
        if cpu_count:
            return max(1, cpu_count - 1)  # 留一个核心给系统
        return 2
    
    def get_memory_usage(self) -> Dict[str, float]:
        """
        获取内存使用情况
        
        Returns:
            内存使用信息
        """
        mem = psutil.virtual_memory()
        return {
            'total_gb': mem.total / (1024 ** 3),
            'available_gb': mem.available / (1024 ** 3),
            'used_gb': mem.used / (1024 ** 3),
            'percent': mem.percent
        }
    
    def get_cpu_usage(self) -> Dict[str, Any]:
        """
        获取CPU使用情况
        
        Returns:
            CPU使用信息
        """
        return {
            'percent': psutil.cpu_percent(interval=0.1),
            'count': psutil.cpu_count(),
            'freq_mhz': psutil.cpu_freq().current if psutil.cpu_freq() else None
        }
    
    def check_admin_privileges(self) -> bool:
        """
        检查是否有管理员权限
        
        Returns:
            是否有管理员权限
        """
        try:
            if self._detector.is_windows():
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False


# 全局实例
_platform_detector = PlatformDetector()
_platform_adapter = PlatformAdapter()
_interface_detector = NetworkInterfaceDetector()


def get_platform_type() -> PlatformType:
    """获取平台类型"""
    return _platform_detector.detect()


def get_platform_config() -> Dict[str, Any]:
    """获取平台配置"""
    return _platform_adapter.get_config()


def get_system_info() -> SystemInfo:
    """获取系统信息"""
    return _platform_detector.get_system_info()


def is_windows() -> bool:
    """是否在Windows上运行"""
    return _platform_detector.is_windows()


def is_linux() -> bool:
    """是否在Linux上运行"""
    return _platform_detector.is_linux()


def is_macos() -> bool:
    """是否在macOS上运行"""
    return _platform_detector.is_macos()


def is_raspberry_pi() -> bool:
    """是否在树莓派上运行"""
    return _platform_detector.is_raspberry_pi()


def get_memory_usage() -> Dict[str, float]:
    """获取内存使用情况"""
    return _platform_adapter.get_memory_usage()


def get_cpu_usage() -> Dict[str, Any]:
    """获取CPU使用情况"""
    return _platform_adapter.get_cpu_usage()


def get_network_interfaces() -> List[Dict[str, Any]]:
    """获取网络接口列表"""
    return _interface_detector.get_all_interfaces()


def get_default_interface() -> Optional[str]:
    """获取默认网络接口"""
    return _interface_detector.get_default_interface()


def list_network_interfaces() -> None:
    """列出所有网络接口"""
    _interface_detector.list_interfaces()


def check_admin() -> bool:
    """检查管理员权限"""
    return _platform_adapter.check_admin_privileges()


if __name__ == "__main__":
    # 测试平台检测
    print("=" * 60)
    print("Platform Detection Test")
    print("=" * 60)
    
    info = get_system_info()
    print(f"Platform Type: {info.platform_type.value}")
    print(f"OS Name: {info.os_name}")
    print(f"Machine: {info.machine}")
    print(f"Processor: {info.processor}")
    print(f"System: {info.system}")
    print(f"Python: {info.python_version}")
    print(f"CPU Count: {info.cpu_count}")
    print(f"Memory: {info.memory_gb:.2f} GB")
    print(f"64-bit: {info.is_64bit}")
    print(f"Admin Privileges: {check_admin()}")
    
    print("\n" + "=" * 60)
    print("Platform Config")
    print("=" * 60)
    config = get_platform_config()
    for key, value in config.items():
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 60)
    print("System Resources")
    print("=" * 60)
    print(f"Memory: {get_memory_usage()}")
    print(f"CPU: {get_cpu_usage()}")
    
    print("\n")
    list_network_interfaces()
