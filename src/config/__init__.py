"""
Edge-IDS 配置管理模块
提供统一的配置加载和管理功能
"""

from .settings import Settings, get_settings
from .constants import *

__all__ = ['Settings', 'get_settings']
