import json
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

from ..utils.logger import LoggerMixin
from ..utils.platform_info import get_system_info, get_memory_usage, get_cpu_usage


@dataclass
class SystemStatus:
    """系统状态数据类"""
    is_running: bool = False
    packets_captured: int = 0
    packets_dropped: int = 0
    flows_analyzed: int = 0
    flows_active: int = 0
    attacks_detected: int = 0
    attacks_total: int = 0
    avg_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    start_time: Optional[str] = None
    uptime_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_running': self.is_running,
            'packets_captured': self.packets_captured,
            'packets_dropped': self.packets_dropped,
            'flows_analyzed': self.flows_analyzed,
            'flows_active': self.flows_active,
            'attacks_detected': self.attacks_detected,
            'attacks_total': self.attacks_total,
            'avg_latency_ms': round(self.avg_latency_ms, 2),
            'max_latency_ms': round(self.max_latency_ms, 2),
            'start_time': self.start_time,
            'uptime_seconds': round(self.uptime_seconds, 2),
        }


class DashboardServer(LoggerMixin):
    """
    Web仪表盘服务器
    
    提供实时监控界面和REST API
    """
    
    def __init__(
        self,
        host: str = '0.0.0.0',
        port: int = 8080,
        debug: bool = False,
        template_folder: str = 'templates',
        static_folder: str = 'static'
    ):
        """
        初始化仪表盘服务器
        
        Args:
            host: 主机地址
            port: 端口号
            debug: 是否调试模式
            template_folder: 模板文件夹
            static_folder: 静态文件文件夹
        """
        super().__init__()
        
        self.host = host
        self.port = port
        self.debug = debug
        
        # 创建Flask应用
        self.app = Flask(
            __name__,
            template_folder=template_folder,
            static_folder=static_folder
        )
        CORS(self.app)
        
        # 系统状态
        self._status = SystemStatus()
        self._status_lock = threading.Lock()
        
        # 回调函数
        self._callbacks: Dict[str, Callable] = {}
        
        # 注册路由
        self._register_routes()
        
        self.logger.info(f"DashboardServer initialized: {host}:{port}")
    
    def _register_routes(self):
        """注册Flask路由"""
        
        @self.app.route('/')
        def index():
            """主页面"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/status')
        def api_status():
            """获取系统状态API"""
            with self._status_lock:
                return jsonify(self._status.to_dict())
        
        @self.app.route('/api/system')
        def api_system():
            """获取系统信息API"""
            info = get_system_info()
            return jsonify({
                'platform': info.platform_type.value,
                'machine': info.machine,
                'processor': info.processor,
                'system': info.system,
                'python_version': info.python_version,
                'cpu_count': info.cpu_count,
                'memory_gb': round(info.memory_gb, 2),
                'is_64bit': info.is_64bit,
            })
        
        @self.app.route('/api/resources')
        def api_resources():
            """获取资源使用API"""
            return jsonify({
                'memory': get_memory_usage(),
                'cpu': get_cpu_usage(),
                'timestamp': datetime.now().isoformat()
            })
        
        @self.app.route('/api/stats')
        def api_stats():
            """获取完整统计信息API"""
            with self._status_lock:
                return jsonify({
                    'timestamp': datetime.now().isoformat(),
                    'status': self._status.to_dict(),
                    'system': {
                        'platform': get_system_info().platform_type.value,
                        'resources': {
                            'memory': get_memory_usage(),
                            'cpu': get_cpu_usage(),
                        }
                    }
                })
        
        @self.app.route('/api/control/start', methods=['POST'])
        def api_control_start():
            """启动检测API"""
            if 'start' in self._callbacks:
                try:
                    self._callbacks['start']()
                    return jsonify({'success': True, 'message': 'Detection started'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)}), 500
            return jsonify({'success': False, 'error': 'Start callback not registered'}), 400
        
        @self.app.route('/api/control/stop', methods=['POST'])
        def api_control_stop():
            """停止检测API"""
            if 'stop' in self._callbacks:
                try:
                    self._callbacks['stop']()
                    return jsonify({'success': True, 'message': 'Detection stopped'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)}), 500
            return jsonify({'success': False, 'error': 'Stop callback not registered'}), 400
        
        @self.app.route('/api/history')
        def api_history():
            """获取历史数据API"""
            # TODO: 实现历史数据查询
            return jsonify({
                'attacks': [],
                'flows': [],
            })
    
    def register_callback(self, name: str, callback: Callable):
        """
        注册回调函数
        
        Args:
            name: 回调名称
            callback: 回调函数
        """
        self._callbacks[name] = callback
        self.logger.debug(f"Registered callback: {name}")
    
    def update_status(self, **kwargs):
        """
        更新系统状态
        
        Args:
            **kwargs: 状态字段
        """
        with self._status_lock:
            for key, value in kwargs.items():
                if hasattr(self._status, key):
                    setattr(self._status, key, value)
        
        self.logger.debug(f"Status updated: {kwargs}")
    
    def get_status(self) -> Dict[str, Any]:
        """获取当前状态"""
        with self._status_lock:
            return self._status.to_dict()
    
    def run(self, threaded: bool = False):
        """
        运行服务器
        
        Args:
            threaded: 是否在新线程中运行
        """
        if threaded:
            server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            server_thread.start()
            self.logger.info(f"Dashboard server started in background thread")
        else:
            self._run_server()
    
    def _run_server(self):
        """运行服务器（内部方法）"""
        self.logger.info(f"Starting dashboard server on http://{self.host}:{self.port}")
        self.app.run(
            host=self.host,
            port=self.port,
            debug=self.debug,
            use_reloader=False  # 禁用重载器，避免多线程问题
        )


# 全局仪表盘实例
_dashboard_instance: Optional[DashboardServer] = None


def get_dashboard(
    host: str = '0.0.0.0',
    port: int = 8080,
    debug: bool = False
) -> DashboardServer:
    """
    获取仪表盘单例实例
    
    Args:
        host: 主机地址
        port: 端口号
        debug: 是否调试模式
    
    Returns:
        DashboardServer实例
    """
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = DashboardServer(
            host=host,
            port=port,
            debug=debug
        )
    return _dashboard_instance


def update_dashboard_status(**kwargs):
    """
    更新仪表盘状态（便捷函数）
    
    Args:
        **kwargs: 状态字段
    """
    global _dashboard_instance
    if _dashboard_instance:
        _dashboard_instance.update_status(**kwargs)


def create_dashboard(config: Optional[Any] = None) -> DashboardServer:
    """
    工厂函数：根据配置创建DashboardServer实例
    
    Args:
        config: 配置对象（可选）
    
    Returns:
        DashboardServer实例
    """
    if config:
        return DashboardServer(
            host=config.web.host,
            port=config.web.port,
            debug=config.web.debug
        )
    return DashboardServer()
