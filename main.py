import sys
import time
import signal
import argparse
from pathlib import Path
from typing import Optional

# 添加项目根目录到Python路径
ROOT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT_DIR))

from src.config import get_settings
from src.utils.logger import setup_logging, get_logger
from src.utils.exceptions import EdgeIDSException
from src.utils.platform_info import (
    is_windows, is_linux, check_admin, get_default_interface,
    list_network_interfaces, get_platform_type
)
from src.capture.packet_capture import PacketCapture, create_packet_capture
from src.features.flow_features import FeatureExtractor, create_feature_extractor
from src.inference.detector import IDSDetector, create_detector

# 可选导入Web模块
try:
    from src.web.dashboard import create_dashboard
    HAS_DASHBOARD = True
except ImportError:
    HAS_DASHBOARD = False
    create_dashboard = None


class EdgeIDS:
    def __init__(self, config_path: Optional[str] = None):
        self.config = get_settings(config_path)

        setup_logging(level=self.config.log.level, log_dir=self.config.log.log_dir)
        self.logger = get_logger(__name__)

        self.capture: Optional[PacketCapture] = None
        self.extractor: Optional[FeatureExtractor] = None
        self.detector: Optional[IDSDetector] = None
        self.dashboard: Optional[Any] = None

        self._is_running = False
        self._start_time: Optional[float] = None

        self._stats = {
            'packets_processed': 0,
            'flows_analyzed': 0,
            'attacks_detected': 0,
            'total_attacks': 0,
        }

        self.logger.info(f"Edge-IDS v1.0 初始化完成 | 平台: {get_platform_type()}")

    def initialize(self) -> 'EdgeIDS':
        """初始化所有组件（重点优化接口检测）"""
        self.logger.info("正在初始化组件...")

        # === 自动处理网络接口 ===
        if self.config.capture.interface in ["auto", "Auto", None, ""]:
            default_iface = get_default_interface()
            if default_iface:
                self.config.capture.interface = default_iface
                self.logger.info(f"自动检测到网络接口 → {default_iface}")
            else:
                self.logger.warning("无法自动检测接口，默认使用 eth0")
                self.config.capture.interface = "eth0"

        # 初始化捕获器
        self.capture = create_packet_capture(self.config)
        self.logger.info(f"数据包捕获器初始化完成 → 接口: {self.config.capture.interface}")

        # 初始化其他组件
        self.extractor = create_feature_extractor(self.config)
        self.logger.info(f"特征提取器初始化完成")

        self.detector = create_detector(self.config)
        self.logger.info(f"检测器初始化完成")

        return self

    # 其他方法保持不变（_packet_callback, _update_dashboard 等）
    def _packet_callback(self, packet_info):
        try:
            features = self.extractor.process_packet(packet_info)
            if features is not None:
                self._stats['flows_analyzed'] += 1
                result = self.detector.predict(features)

                if result.is_attack(self.config.inference.alert_threshold):
                    self._stats['attacks_detected'] += 1
                    self._stats['total_attacks'] += 1
                    self.logger.warning(f"检测到攻击！置信度: {result.confidence:.4f}")

                if self.dashboard:
                    self._update_dashboard()

            self._stats['packets_processed'] += 1
        except Exception as e:
            self.logger.error(f"数据包处理错误: {e}")

    def _update_dashboard(self):
        if not self.dashboard:
            return
        # ...（保持你原来的实现）
        pass

    def start_detection(self):
        if self._is_running:
            return
        self.logger.info(f"开始实时捕获流量 → {self.config.capture.interface}")
        self.capture.register_callback(self._packet_callback)
        self.capture.start_live_capture()
        self._is_running = True
        self._start_time = time.time()

    def stop_detection(self):
        if not self._is_running:
            return
        self.logger.info("正在停止检测...")
        if self.capture:
            self.capture.stop_capture()
        self._is_running = False

    def run(self, mode: str = 'full', interface: Optional[str] = None):
        if interface:
            self.config.capture.interface = interface
            self.logger.info(f"使用命令行指定接口: {interface}")
            # 重新创建捕获器
            if self.capture:
                self.capture.stop_capture()
            self.capture = create_packet_capture(self.config)

        try:
            if mode == 'full':
                self.start_dashboard()
                self.start_detection()
                self._run_main_loop()
            elif mode == 'dashboard':
                self.start_dashboard()
                self._run_main_loop()
            elif mode == 'capture':
                self.start_detection()
                self._run_main_loop()
        except KeyboardInterrupt:
            self.logger.info("收到中断信号，正在关闭...")
        finally:
            self.shutdown()

    def start_dashboard(self):
        if not HAS_DASHBOARD:
            self.logger.warning("Web仪表盘不可用")
            return
        self.dashboard = create_dashboard(self.config)
        self.dashboard.register_callback('start', self.start_detection)
        self.dashboard.register_callback('stop', self.stop_detection)
        self.dashboard.run(threaded=True)
        self.logger.info(f"Web仪表盘已启动: http://{self.config.web.host}:{self.config.web.port}")

    def _run_main_loop(self):
        self.logger.info("系统运行中，按 Ctrl+C 停止...")
        try:
            while True:
                if self.dashboard and self._is_running:
                    self._update_dashboard()
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    def shutdown(self):
        self.stop_detection()
        self._print_stats()
        self.logger.info("系统已关闭")

    def _print_stats(self):
        # ... 保持你原来的统计输出
        pass


# ====================== 启动相关 ======================
def parse_arguments():
    parser = argparse.ArgumentParser(description='Edge-IDS 边缘入侵检测系统')
    parser.add_argument('--mode', choices=['full', 'capture', 'dashboard'], default='full')
    parser.add_argument('--interface', default=None, help='指定网络接口')
    parser.add_argument('--config', default='config.yaml')
    parser.add_argument('--list-interfaces', action='store_true')
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.list_interfaces:
        list_network_interfaces()
        return

    if args.mode != 'dashboard':
        if not check_admin():
            print("请以管理员权限（Windows）或 sudo（Linux）运行！")
            sys.exit(1)

    try:
        ids = EdgeIDS(config_path=args.config)
        ids.initialize()
        ids.run(mode=args.mode, interface=args.interface)
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()