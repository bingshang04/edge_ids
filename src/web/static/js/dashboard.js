
// 配置
const CONFIG = {
    updateInterval: 1000,  // 状态更新间隔（毫秒）
    resourceUpdateInterval: 2000,  // 资源更新间隔
};

// 状态
let isRunning = false;
let updateTimer = null;
let resourceTimer = null;

/**
 * 初始化仪表盘
 */
function initDashboard() {
    loadSystemInfo();
    startStatusUpdates();
    startResourceUpdates();
}

/**
 * 加载系统信息
 */
async function loadSystemInfo() {
    try {
        const response = await fetch('/api/system');
        const data = await response.json();
        
        document.getElementById('info-platform').textContent = data.platform;
        document.getElementById('info-processor').textContent = data.processor || 'Unknown';
        document.getElementById('info-system').textContent = data.system;
        document.getElementById('info-python').textContent = data.python_version;
        document.getElementById('info-cpu').textContent = data.cpu_count;
        document.getElementById('info-memory').textContent = data.memory_gb + ' GB';
        document.getElementById('platform').textContent = data.platform;
    } catch (error) {
        console.error('Failed to load system info:', error);
    }
}

/**
 * 开始状态更新
 */
function startStatusUpdates() {
    updateStatus();  // 立即执行一次
    updateTimer = setInterval(updateStatus, CONFIG.updateInterval);
}

/**
 * 停止状态更新
 */
function stopStatusUpdates() {
    if (updateTimer) {
        clearInterval(updateTimer);
        updateTimer = null;
    }
}

/**
 * 更新状态
 */
async function updateStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        // 更新UI
        document.getElementById('packets').textContent = formatNumber(data.packets_captured);
        document.getElementById('packets-dropped').textContent = `丢弃: ${formatNumber(data.packets_dropped)}`;
        document.getElementById('flows').textContent = formatNumber(data.flows_analyzed);
        document.getElementById('flows-active').textContent = `活跃: ${formatNumber(data.flows_active)}`;
        document.getElementById('attacks').textContent = formatNumber(data.attacks_detected);
        document.getElementById('attacks-total').textContent = `总计: ${formatNumber(data.attacks_total)}`;
        document.getElementById('latency').textContent = data.avg_latency_ms.toFixed(1) + 'ms';
        document.getElementById('latency-max').textContent = `最大: ${data.max_latency_ms.toFixed(1)}ms`;
        
        // 更新运行时间
        const uptime = formatDuration(data.uptime_seconds);
        document.getElementById('uptime').textContent = `运行时间: ${uptime}`;
        
        // 更新状态指示器
        const statusEl = document.getElementById('system-status');
        if (data.is_running) {
            statusEl.textContent = '运行中';
            statusEl.className = 'status-running';
            isRunning = true;
        } else {
            statusEl.textContent = '停止';
            statusEl.className = 'status-stopped';
            isRunning = false;
        }
        
        // 更新按钮状态
        updateButtonStates();
        
    } catch (error) {
        console.error('Failed to update status:', error);
    }
}

/**
 * 开始资源更新
 */
function startResourceUpdates() {
    updateResources();  // 立即执行一次
    resourceTimer = setInterval(updateResources, CONFIG.resourceUpdateInterval);
}

/**
 * 停止资源更新
 */
function stopResourceUpdates() {
    if (resourceTimer) {
        clearInterval(resourceTimer);
        resourceTimer = null;
    }
}

/**
 * 更新资源使用情况
 */
async function updateResources() {
    try {
        const response = await fetch('/api/resources');
        const data = await response.json();
        
        // 更新CPU
        const cpuPercent = data.cpu.percent;
        document.getElementById('cpu-bar').style.width = cpuPercent + '%';
        document.getElementById('cpu-value').textContent = cpuPercent.toFixed(1) + '%';
        
        // 更新内存
        const memPercent = data.memory.percent;
        document.getElementById('memory-bar').style.width = memPercent + '%';
        document.getElementById('memory-value').textContent = memPercent.toFixed(1) + '%';
        
        // 高亮警告
        if (cpuPercent > 80) {
            document.getElementById('cpu-bar').classList.add('warning');
        } else {
            document.getElementById('cpu-bar').classList.remove('warning');
        }
        
        if (memPercent > 80) {
            document.getElementById('memory-bar').classList.add('warning');
        } else {
            document.getElementById('memory-bar').classList.remove('warning');
        }
        
    } catch (error) {
        console.error('Failed to update resources:', error);
    }
}

/**
 * 更新按钮状态
 */
function updateButtonStates() {
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');
    
    btnStart.disabled = isRunning;
    btnStop.disabled = !isRunning;
}

/**
 * 开始检测
 */
async function startDetection() {
    try {
        const btnStart = document.getElementById('btn-start');
        btnStart.disabled = true;
        btnStart.textContent = '⏳ 启动中...';
        
        const response = await fetch('/api/control/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('检测已启动', 'success');
        } else {
            showNotification('启动失败: ' + data.error, 'error');
        }
    } catch (error) {
        console.error('Failed to start detection:', error);
        showNotification('启动失败', 'error');
    } finally {
        const btnStart = document.getElementById('btn-start');
        btnStart.textContent = '▶️ 开始检测';
    }
}

/**
 * 停止检测
 */
async function stopDetection() {
    try {
        const btnStop = document.getElementById('btn-stop');
        btnStop.disabled = true;
        btnStop.textContent = '⏳ 停止中...';
        
        const response = await fetch('/api/control/stop', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('检测已停止', 'success');
        } else {
            showNotification('停止失败: ' + data.error, 'error');
        }
    } catch (error) {
        console.error('Failed to stop detection:', error);
        showNotification('停止失败', 'error');
    } finally {
        const btnStop = document.getElementById('btn-stop');
        btnStop.textContent = '⏹️ 停止检测';
    }
}

/**
 * 显示通知
 */
function showNotification(message, type = 'info') {
    // 创建通知元素
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // 样式
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        border-radius: 8px;
        color: white;
        font-weight: 500;
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;
    
    // 根据类型设置颜色
    const colors = {
        success: '#27ae60',
        error: '#e74c3c',
        warning: '#f39c12',
        info: '#3498db'
    };
    notification.style.backgroundColor = colors[type] || colors.info;
    
    // 添加动画样式
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    `;
    document.head.appendChild(style);
    
    // 添加到页面
    document.body.appendChild(notification);
    
    // 3秒后自动移除
    setTimeout(() => {
        notification.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
}

/**
 * 格式化数字
 */
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

/**
 * 格式化持续时间
 */
function formatDuration(seconds) {
    if (seconds < 60) {
        return Math.floor(seconds) + 's';
    } else if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        const secs = Math.floor(seconds % 60);
        return `${mins}m ${secs}s`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    }
}

/**
 * 页面加载完成后初始化
 */
document.addEventListener('DOMContentLoaded', initDashboard);

/**
 * 页面卸载时清理
 */
window.addEventListener('beforeunload', () => {
    stopStatusUpdates();
    stopResourceUpdates();
});
