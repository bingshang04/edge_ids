"""
Edge-IDS 导入测试脚本
验证所有模块可以正确导入
"""

import sys
from pathlib import Path

# 添加项目根目录到Python路径
ROOT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT_DIR))

def test_imports():
    """测试所有模块导入"""
    errors = []
    
    # 测试配置模块
    try:
        from src.config import get_settings
        from src.config.constants import PROJECT_NAME
        print("配置模块导入成功")
    except Exception as e:
        errors.append(f"配置模块: {e}")
        print(f"配置模块导入失败: {e}")
    
    # 测试工具模块
    try:
        from src.utils.logger import get_logger
        from src.utils.exceptions import EdgeIDSException
        from src.utils.helpers import ensure_dir
        from src.utils.platform_info import get_platform_type
        print("工具模块导入成功")
    except Exception as e:
        errors.append(f"工具模块: {e}")
        print(f"工具模块导入失败: {e}")
    
    # 测试捕获模块
    try:
        from src.capture.packet_capture import PacketCapture
        print("捕获模块导入成功")
    except Exception as e:
        errors.append(f"捕获模块: {e}")
        print(f"捕获模块导入失败: {e}")
    
    # 测试特征模块
    try:
        from src.features.flow_features import FeatureExtractor
        print("特征模块导入成功")
    except Exception as e:
        errors.append(f"特征模块: {e}")
        print(f"特征模块导入失败: {e}")
    
    # 测试模型模块
    try:
        from src.models.tcn_model import TCN
        print("模型模块导入成功")
    except Exception as e:
        errors.append(f"模型模块: {e}")
        print(f"模型模块导入失败: {e}")
    
    # 测试推理模块
    try:
        from src.inference.detector import IDSDetector
        print("推理模块导入成功")
    except Exception as e:
        errors.append(f"推理模块: {e}")
        print(f"推理模块导入失败: {e}")
    
    # 测试Web模块（可选，需要flask）
    try:
        from src.web.dashboard import DashboardServer
        print("Web模块导入成功")
    except ImportError as e:
        if 'flask' in str(e).lower():
            print("Web模块需要flask（可选依赖）")
        else:
            errors.append(f"Web模块: {e}")
            print(f"Web模块导入失败: {e}")
    except Exception as e:
        errors.append(f"Web模块: {e}")
        print(f"Web模块导入失败: {e}")
    
    # 测试主程序
    try:
        from main import EdgeIDS
        print("主程序导入成功")
    except Exception as e:
        errors.append(f"主程序: {e}")
        print(f"主程序导入失败: {e}")
    
    # 总结
    print("\n" + "=" * 50)
    if not errors:
        print("所有模块导入成功！")
        return True
    else:
        print(f"{len(errors)} 个模块导入失败")
        return False


if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)
