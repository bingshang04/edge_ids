"""
CICIDS2017 跨数据集测试脚本（完整修复版 v3）
- 修复：'bool' object has no attribute 'astype'
- 修复：特征维度不匹配（19 vs 48）
"""

import pandas as pd
import numpy as np
import torch
import joblib
import os
import glob
from src.models.tcn_model import TCN

# ====================== 配置 ======================
MODEL_PATH = '../data/models/tcn_model_3.0.pth'
SCALER_PATH = '../data/models/unsw_scaler3.0.joblib'
LE_PROTO_PATH = '../data/models/le_proto.joblib'
LE_SERVICE_PATH = '../data/models/le_service.joblib'
LE_STATE_PATH = '../data/models/le_state.joblib'

CICIDS_DIR = '../data/raw/CICIDS2017'
SEQ_LENGTH = 10

# ====================== 加载预处理器 ======================
print("正在加载 UNSW-NB15 训练时的预处理器...")
scaler = joblib.load(SCALER_PATH)
le_proto = joblib.load(LE_PROTO_PATH)
le_service = joblib.load(LE_SERVICE_PATH)
le_state = joblib.load(LE_STATE_PATH)
print("预处理器加载成功！")
print(f"  - Protocol 类别数: {len(le_proto.classes_)}")
print(f"  - Service 类别数: {len(le_service.classes_)}")
print(f"  - State 类别数: {len(le_state.classes_)}")
print(f"  - Scaler 期望特征维度: {scaler.n_features_in_}")

# ====================== 加载模型 ======================
model = TCN(
    input_dim=48,
    num_classes=2,
    num_channels=[128, 256, 256],
    kernel_size=5,
    dropout=0.3
)
model.load_state_dict(torch.load(MODEL_PATH, map_location='cpu'))
model.eval()
print("模型加载成功！\n")

# ====================== 加载并合并 CICIDS2017 ======================
print(f"正在读取文件夹: {CICIDS_DIR}")
csv_files = glob.glob(os.path.join(CICIDS_DIR, "*.csv"))
print(f"找到 {len(csv_files)} 个 CSV 文件")

dfs = []
for file in csv_files:
    print(f"读取 → {os.path.basename(file)}")
    df = pd.read_csv(file, low_memory=False)
    dfs.append(df)

cic_df = pd.concat(dfs, ignore_index=True)
print(f"合并完成，总样本数: {len(cic_df):,}\n")

# 查看所有列名
print("CICIDS2017 所有列名:")
print(cic_df.columns.tolist())
print()

# 清洗数据
cic_df = cic_df.replace([np.inf, -np.inf], np.nan)
cic_df = cic_df.dropna()

# ====================== 生成标签 ======================
print("正在生成二分类标签...")

possible_label_cols = ['Label', 'label', ' Label', 'label ', 'Class', 'class']
label_col = None
for col in possible_label_cols:
    if col in cic_df.columns:
        label_col = col
        print(f"✓ 找到标签列: '{col}'")
        break

if label_col is None:
    print("✗ 未找到标签列！")
    print(cic_df.columns.tolist()[:15])
    raise KeyError("请检查CSV文件列名")

cic_df['label'] = (~cic_df[label_col].astype(str).str.lower().str.contains('benign')).astype(int)
print(f"攻击样本比例: {cic_df['label'].mean():.2%} ({cic_df['label'].sum():,} 个攻击样本)\n")

# ====================== 特征映射 ======================
print("正在进行特征映射...")

# 基础特征映射
cic_df['dur'] = cic_df.get('Flow Duration', pd.Series([0]*len(cic_df))) / 1_000_000.0
cic_df['spkts'] = cic_df.get('Total Fwd Packets', cic_df.get('Tot Fwd Pkts', pd.Series([0]*len(cic_df))))
cic_df['dpkts'] = cic_df.get('Total Backward Packets', cic_df.get('Tot Bwd Pkts', pd.Series([0]*len(cic_df))))
cic_df['sbytes'] = cic_df.get('Total Length of Fwd Packets', cic_df.get('TotLen Fwd Pkts', pd.Series([0]*len(cic_df))))
cic_df['dbytes'] = cic_df.get('Total Length of Bwd Packets', cic_df.get('TotLen Bwd Pkts', pd.Series([0]*len(cic_df))))
cic_df['rate'] = cic_df.get('Flow Packets/s', cic_df.get('Flow Pkts/s', pd.Series([0]*len(cic_df))))

# TTL 值（使用默认值）
cic_df['sttl'] = 254
cic_df['dttl'] = 252

# 负载
cic_df['sload'] = cic_df.get('Fwd Packets/s', pd.Series([0]*len(cic_df))) * cic_df['sbytes']
cic_df['dload'] = cic_df.get('Bwd Packets/s', pd.Series([0]*len(cic_df))) * cic_df['dbytes']

# Loss 相关
cic_df['sloss'] = cic_df.get('Fwd PSH Flags', pd.Series([0]*len(cic_df))) + cic_df.get('Fwd URG Flags', pd.Series([0]*len(cic_df)))
cic_df['dloss'] = cic_df.get('Bwd PSH Flags', pd.Series([0]*len(cic_df))) + cic_df.get('Bwd URG Flags', pd.Series([0]*len(cic_df)))

# Window 大小
cic_df['swin'] = cic_df.get('Fwd Window Size', cic_df.get('Fwd Win Bytes', pd.Series([0]*len(cic_df))))
cic_df['dwin'] = cic_df.get('Bwd Window Size', cic_df.get('Bwd Win Bytes', pd.Series([0]*len(cic_df))))

# TCP 序列号（CICIDS2017 没有，设为0）
cic_df['stcpb'] = 0
cic_df['dtcpb'] = 0

# 平均包大小
cic_df['smeansz'] = cic_df['sbytes'] / (cic_df['spkts'] + 1e-6)
cic_df['dmeansz'] = cic_df['dbytes'] / (cic_df['dpkts'] + 1e-6)

# HTTP 相关（CICIDS2017 可能没有）
cic_df['trans_depth'] = 0
cic_df['res_bdy_len'] = 0

# 抖动和间隔时间
cic_df['sjit'] = cic_df.get('Fwd IAT Mean', pd.Series([0]*len(cic_df)))
cic_df['djit'] = cic_df.get('Bwd IAT Mean', pd.Series([0]*len(cic_df)))
cic_df['sintpkt'] = cic_df['sjit']
cic_df['dintpkt'] = cic_df['djit']

# TCP RTT 相关
cic_df['tcprtt'] = cic_df.get('Flow IAT Mean', pd.Series([0]*len(cic_df)))
cic_df['synack'] = cic_df.get('SYN Flag Count', pd.Series([0]*len(cic_df)))
cic_df['ackdat'] = cic_df.get('ACK Flag Count', pd.Series([0]*len(cic_df)))

# 修复：is_sm_ips_ports - 检查源IP和目的IP是否相同
# CICIDS2017 列名可能是 'Source IP' / 'Destination IP' 或 'Src IP' / 'Dst IP'
src_ip_col = 'Source IP' if 'Source IP' in cic_df.columns else ('Src IP' if 'Src IP' in cic_df.columns else None)
dst_ip_col = 'Destination IP' if 'Destination IP' in cic_df.columns else ('Dst IP' if 'Dst IP' in cic_df.columns else None)
src_port_col = 'Source Port' if 'Source Port' in cic_df.columns else ('Src Port' if 'Src Port' in cic_df.columns else None)
dst_port_col = 'Destination Port' if 'Destination Port' in cic_df.columns else ('Dst Port' if 'Dst Port' in cic_df.columns else None)

if src_ip_col and dst_ip_col and src_port_col and dst_port_col:
    cic_df['is_sm_ips_ports'] = ((cic_df[src_ip_col] == cic_df[dst_ip_col]) &
                                 (cic_df[src_port_col] == cic_df[dst_port_col])).astype(int)
else:
    cic_df['is_sm_ips_ports'] = 0

# FTP 登录标记
cic_df['is_ftp_login'] = cic_df.get('FTP Command Count', pd.Series([0]*len(cic_df)))

# 状态 TTL 计数
cic_df['ct_state_ttl'] = cic_df.get('Active Mean', pd.Series([0]*len(cic_df)))

# HTTP 方法计数
cic_df['ct_flw_http_mthd'] = cic_df.get('HTTP Method Count', pd.Series([0]*len(cic_df)))

# FTP 命令计数
cic_df['ct_ftp_cmd'] = cic_df['is_ftp_login']

# 连接计数特征
cic_df['ct_srv_src'] = cic_df.get('Flow Byts/s', pd.Series([0]*len(cic_df)))
cic_df['ct_srv_dst'] = cic_df.get('Flow Pkts/s', pd.Series([0]*len(cic_df)))
cic_df['ct_dst_ltm'] = cic_df.get('Active Mean', pd.Series([0]*len(cic_df)))
cic_df['ct_src_ltm'] = cic_df.get('Idle Mean', pd.Series([0]*len(cic_df)))
cic_df['ct_src_dport_ltm'] = cic_df.get('Active Std', pd.Series([0]*len(cic_df)))
cic_df['ct_dst_sport_ltm'] = cic_df.get('Idle Std', pd.Series([0]*len(cic_df)))
cic_df['ct_dst_src_ltm'] = cic_df.get('Active Max', pd.Series([0]*len(cic_df)))

# ====================== 类别特征处理 ======================
print("\n处理类别特征...")

# 智能查找协议列
possible_proto_cols = ['Protocol', 'protocol', ' Proto', 'proto', ' Protocol']
proto_col = None
for col in possible_proto_cols:
    if col in cic_df.columns:
        proto_col = col
        print(f"✓ 找到协议列: '{col}'")
        break

if proto_col is None:
    print("⚠️ 未找到协议列，使用默认值 'tcp'")
    proto_values = pd.Series(['tcp'] * len(cic_df))
else:
    proto_values = cic_df[proto_col]
    print(f"  协议列唯一值: {list(proto_values.unique())[:10]}")

# 协议值标准化
def normalize_protocol(val):
    if pd.isna(val):
        return 'tcp'
    val_str = str(val).strip().lower()
    protocol_map = {
        '6': 'tcp', '17': 'udp', '1': 'icmp', '2': 'igmp',
        'tcp': 'tcp', 'udp': 'udp', 'icmp': 'icmp', '0': 'tcp'
    }
    return protocol_map.get(val_str, 'tcp')

proto_normalized = proto_values.apply(normalize_protocol)

# 使用训练时的编码器
known_protos = set(le_proto.classes_)
default_proto = le_proto.classes_[0] if len(le_proto.classes_) > 0 else 'tcp'
proto_fixed = proto_normalized.apply(lambda x: x if x in known_protos else default_proto)
unknown_count = (proto_normalized != proto_fixed).sum()
if unknown_count > 0:
    print(f"  ⚠️ {unknown_count:,} 个样本的协议被替换为 '{default_proto}'")

cic_df['proto'] = le_proto.transform(proto_fixed)

# Service 和 State 使用默认值
default_service = le_service.classes_[0] if len(le_service.classes_) > 0 else '-'
cic_df['service'] = le_service.transform([default_service] * len(cic_df))
print(f"  Service 使用默认值: {default_service}")

default_state = le_state.classes_[0] if len(le_state.classes_) > 0 else 'ACC'
cic_df['state'] = le_state.transform([default_state] * len(cic_df))
print(f"  State 使用默认值: {default_state}")

# ====================== 构建 48 维特征向量 ======================
print("\n构建 48 维特征向量...")

# UNSW-NB15 特征列表（48维）
feature_cols = [
    # 基础特征 (18个)
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
    'sload', 'dload', 'sloss', 'dloss', 'swin', 'dwin', 'stcpb', 'dtcpb',
    'smeansz', 'dmeansz',
    # 内容特征 (8个)
    'trans_depth', 'res_bdy_len', 'sjit', 'djit', 'sintpkt', 'dintpkt', 'tcprtt', 'synack',
    # 标记和计数 (13个)
    'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login',
    'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    # 类别特征编码后 (3个)
    'proto', 'service', 'state',
    # 额外填充特征 (6个) - 重复使用关键特征
    'sbytes', 'dbytes', 'spkts', 'dpkts', 'rate', 'dur'
]

# 确保所有列都存在
for col in feature_cols:
    if col not in cic_df.columns:
        print(f"  创建缺失列: {col}")
        cic_df[col] = 0

# 提取特征矩阵
X_cic = cic_df[feature_cols].fillna(0).values
y_cic = cic_df['label'].values

print(f"特征矩阵维度: {X_cic.shape}")

# 标准化
X_cic = scaler.transform(X_cic)

print(f"\n特征处理完成！")
print(f"  - 样本数: {len(X_cic):,}")
print(f"  - 特征维度: {X_cic.shape[1]}")
print(f"  - 攻击样本: {y_cic.sum():,} ({y_cic.mean():.2%})\n")

# ====================== 开始测试 ======================
print("开始序列测试（seq_length=10）")

tp = fp = tn = fn = 0
total_seq = len(X_cic) - SEQ_LENGTH + 1

for i in range(total_seq):
    seq = X_cic[i:i + SEQ_LENGTH]
    label = y_cic[i + SEQ_LENGTH - 1]

    tensor = torch.FloatTensor(seq).unsqueeze(0)

    with torch.no_grad():
        output = model(tensor)
        pred = torch.argmax(output, dim=1).item()

    if pred == 1 and label == 1:
        tp += 1
    elif pred == 1 and label == 0:
        fp += 1
    elif pred == 0 and label == 0:
        tn += 1
    else:
        fn += 1

    if (i + 1) % 50000 == 0:
        print(f"  已处理 {i+1:,}/{total_seq:,} 序列 ({(i+1)/total_seq*100:.1f}%)")

# 计算指标
total = tp + fp + tn + fn
accuracy = (tp + tn) / total if total > 0 else 0
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

print("\n" + "="*80)
print("CICIDS2017 跨数据集测试结果（使用 UNSW-NB15 模型）")
print("="*80)
print(f"总序列数: {total:,}")
print(f"准确率:   {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"精确率:   {precision:.4f}")
print(f"召回率:   {recall:.4f}")
print(f"F1 分数:  {f1:.4f}")
print(f"\n混淆矩阵:")
print(f"  真负例 (TN): {tn:,}    假正例 (FP): {fp:,}")
print(f"  假负例 (FN): {fn:,}    真正例 (TP): {tp:,}")
if (tp + fn) > 0:
    print(f"漏检率:   {fn / (tp + fn) * 100:.2f}%")
    print(f"检出率:   {tp / (tp + fn) * 100:.2f}%")
print("="*80)
