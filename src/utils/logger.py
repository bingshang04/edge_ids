import os
import sys
import logging
import logging.handlers
from pathlib import Path
from typing import Optional

from ..config.constants import LOG_CONFIG, DEFAULT_LOG_DIR


class ColoredFormatter(logging.Formatter):
    """带颜色的日志格式化器"""
    
    # ANSI颜色代码
    COLORS = {
        'DEBUG': '\033[36m',      # 青色
        'INFO': '\033[32m',       # 绿色
        'WARNING': '\033[33m',    # 黄色
        'ERROR': '\033[31m',      # 红色
        'CRITICAL': '\033[35m',   # 紫色
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        # 保存原始级别名称
        original_levelname = record.levelname
        
        # 添加颜色（如果在终端中）
        if sys.stdout.isatty():
            color = self.COLORS.get(record.levelname, '')
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        
        result = super().format(record)
        
        # 恢复原始级别名称
        record.levelname = original_levelname
        
        return result


def setup_logging(
    level: Optional[str] = None,
    log_dir: Optional[str] = None,
    log_to_file: bool = True,
    log_to_console: bool = True,
    format_str: Optional[str] = None,
    date_format: Optional[str] = None,
    max_bytes: int = LOG_CONFIG['max_bytes'],
    backup_count: int = LOG_CONFIG['backup_count']
) -> logging.Logger:
    """
    设置日志系统
    
    Args:
        level: 日志级别 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: 日志文件目录
        log_to_file: 是否写入日志文件
        log_to_console: 是否输出到控制台
        format_str: 日志格式字符串
        date_format: 日期格式字符串
        max_bytes: 单个日志文件最大字节数
        backup_count: 备份文件数量
    
    Returns:
        根日志记录器
    """
    # 使用默认值
    level = level or LOG_CONFIG['level']
    log_dir = log_dir or DEFAULT_LOG_DIR
    format_str = format_str or LOG_CONFIG['format']
    date_format = date_format or LOG_CONFIG['date_format']
    
    # 获取日志级别
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # 清除现有处理器
    root_logger.handlers.clear()
    
    # 创建格式化器
    console_formatter = ColoredFormatter(format_str, datefmt=date_format)
    file_formatter = logging.Formatter(format_str, datefmt=date_format)
    
    # 控制台处理器
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    # 文件处理器
    if log_to_file:
        # 确保日志目录存在
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        
        # 主日志文件
        main_log_file = log_path / 'edge_ids.log'
        file_handler = logging.handlers.RotatingFileHandler(
            main_log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        
        # 错误日志文件（单独记录ERROR及以上级别）
        error_log_file = log_path / 'edge_ids.error.log'
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        root_logger.addHandler(error_handler)
    
    # 设置第三方库日志级别
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('scapy').setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.debug(f"Logging setup complete: level={level}, log_dir={log_dir}")
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    获取指定名称的日志记录器
    
    Args:
        name: 日志记录器名称
    
    Returns:
        日志记录器
    """
    return logging.getLogger(name)


class LoggerMixin:
    """日志混入类，为类提供logger属性"""
    
    @property
    def logger(self) -> logging.Logger:
        """获取类日志记录器"""
        return logging.getLogger(self.__class__.__module__ + '.' + self.__class__.__name__)
