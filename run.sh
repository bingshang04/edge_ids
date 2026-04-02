#!/bin/bash
# Edge-IDS 启动脚本

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 默认配置
MODE="full"
INTERFACE="eth0"
CONFIG="config.yaml"
LOG_LEVEL="INFO"

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --interface)
            INTERFACE="$2"
            shift 2
            ;;
        --config)
            CONFIG="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --help)
            echo "Edge-IDS 启动脚本"
            echo ""
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --mode {full,capture,dashboard}  运行模式 (默认: full)"
            echo "  --interface INTERFACE            网络接口 (默认: eth0)"
            echo "  --config CONFIG                  配置文件 (默认: config.yaml)"
            echo "  --log-level LEVEL                日志级别 (默认: INFO)"
            echo "  --help                           显示帮助"
            echo ""
            echo "示例:"
            echo "  $0                               # 完整模式"
            echo "  $0 --mode dashboard              # 仅仪表盘"
            echo "  $0 --interface wlan0             # 使用wlan0接口"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            exit 1
            ;;
    esac
done

# 检查虚拟环境
if [ -d "venv" ]; then
    echo "激活虚拟环境..."
    source venv/bin/activate
fi

# 检查root权限（捕获模式需要）
if [ "$MODE" != "dashboard" ] && [ "$EUID" -ne 0 ]; then
    echo "警告: 数据包捕获需要root权限，尝试使用sudo..."
    exec sudo "$0" "$@"
fi

# 启动Edge-IDS
echo "========================================"
echo "Edge-IDS 启动"
echo "========================================"
echo "模式: $MODE"
echo "接口: $INTERFACE"
echo "配置: $CONFIG"
echo "日志级别: $LOG_LEVEL"
echo "========================================"

python main.py \
    --mode "$MODE" \
    --interface "$INTERFACE" \
    --config "$CONFIG" \
    --log-level "$LOG_LEVEL"
