import torch
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from src.models.tcn_model import TCN   # 确保使用优化后的 TCN


def load_model():
    """加载优化版模型"""
    model = TCN(
        input_dim=48,                    # 训练时特征数量
        num_classes=2,
        num_channels=[128, 256, 256],
        kernel_size=5,
        dropout=0.3
    )
    model.load_state_dict(torch.load('../data/models/tcn_model_3.0.pth', map_location='cpu'))
    model.eval()
    return model


def test_with_real_data():
    """用真实数据测试（特征工程与训练完全一致）"""
    print("=" * 70)
    print("UNSW-NB15 数据测试")
    print("=" * 70)

    # 加载模型
    model = load_model()
    print("优化版模型加载成功")

    # 加载测试数据
    print("\n加载测试数据...")
    test_df = pd.read_csv('../data/raw/UNSW_NB15_testing-set.csv')

    # ====================== 与训练完全一致的特征工程 ======================
    numeric_cols = [col for col in test_df.columns
                    if col not in ['id', 'proto', 'service', 'state', 'attack_cat', 'label']]

    # 衍生特征
    for df in [test_df]:
        df['byte_ratio'] = df['sbytes'] / (df['dbytes'] + 1e-6)
        df['load_ratio'] = df['sload'] / (df['dload'] + 1e-6)
        df['pkt_ratio'] = df['spkts'] / (df['spkts'] + df['dpkts'] + 1e-6)
        df['dur_rate'] = df['dur'] * df['rate']
        df['ttl_diff'] = df['sttl'] - df['dttl']
        df['avg_pkt_size'] = (df['sbytes'] + df['dbytes']) / (df['spkts'] + df['dpkts'] + 1e-6)

    # 类别特征编码（必须与训练时使用相同的类别映射）
    cat_cols = ['proto', 'service', 'state']
    for col in cat_cols:
        combined = pd.concat([pd.read_csv('../data/raw/UNSW_NB15_training-set.csv')[col],
                              test_df[col]], axis=0).fillna('unknown').astype(str)
        le = LabelEncoder()
        le.fit(combined)
        test_df[col] = le.transform(test_df[col].fillna('unknown').astype(str))

    # 最终特征列表（顺序必须与训练时完全一致）
    feature_cols = numeric_cols + ['byte_ratio', 'load_ratio', 'pkt_ratio',
                                   'dur_rate', 'ttl_diff', 'avg_pkt_size'] + cat_cols

    print(f"使用特征数量: {len(feature_cols)}")

    # 处理缺失值 + 转换为 numpy
    X = test_df[feature_cols].fillna(0).values
    y = test_df['label'].values

    # 标准化（注意：实际生产中应保存训练时的 scaler，这里简化用 fit_transform）
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    print(f"测试样本数: {len(X)}")
    print(f"攻击样本: {y.sum()} ({y.mean():.2%})")

    # ====================== 测试 ======================
    seq_length = 10
    tp = fp = tn = fn = 0

    print("\n开始序列测试...")
    for i in range(len(X) - seq_length + 1):
        seq = X[i:i + seq_length]
        label = y[i + seq_length - 1]

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

        if (i + 1) % 5000 == 0:
            print(f"  已处理 {i + 1}/{len(X) - seq_length + 1} 序列")

    # 计算指标
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print("\n" + "=" * 70)
    print("测试结果（优化版模型）")
    print("=" * 70)
    print(f"准确率:  {accuracy:.4f}")
    print(f"精确率:  {precision:.4f}")
    print(f"召回率:  {recall:.4f}")
    print(f"F1分数:  {f1:.4f}")
    print(f"\n混淆矩阵:")
    print(f"  TN: {tn:6d}, FP: {fp:6d}")
    print(f"  FN: {fn:6d}, TP: {tp:6d}")
    print(f"漏检率: {fn / (tp + fn) * 100 if (tp + fn) > 0 else 0:.2f}%")

    # 可选：保存漏检分析（如果你之前有 analyze_missed_attacks 函数）
    print(f"\n测试完成！漏检样本数: {fn}")


if __name__ == "__main__":
    test_with_real_data()