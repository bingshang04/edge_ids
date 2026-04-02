"""
用真实 UNSW-NB15 数据测试模型
"""

import torch
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from src.models.tcn_model import TCN


def load_model():
    """加载训练好的模型"""
    model = TCN(
        input_dim=39,
        num_classes=2,
        num_channels=[128, 256],
        dropout=0.2
    )
    model.load_state_dict(torch.load('../data/models/tcn_model_optimized.pth', map_location='cpu'))
    model.eval()
    return model


def test_with_real_data():
    """用真实数据测试"""
    print("=" * 60)
    print("用真实 UNSW-NB15 数据测试")
    print("=" * 60)

    # 加载模型
    model = load_model()
    print("✅ 模型加载成功")

    # 加载测试数据
    print("\n加载测试数据...")
    test_df = pd.read_csv('../data/raw/UNSW_NB15_testing-set.csv')

    feature_cols = [col for col in test_df.columns
                    if col not in ['id', 'proto', 'service', 'state', 'attack_cat', 'label']]

    # 处理缺失值
    X = test_df[feature_cols].fillna(0).values
    y = test_df['label'].values

    # 标准化（用训练时的 scaler，这里简化处理）
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    print(f"测试样本数: {len(X)}")
    print(f"攻击样本: {y.sum()} ({y.mean():.2%})")

    # 创建序列
    seq_length = 10
    correct = 0
    tp = fp = tn = fn = 0

    print("\n开始测试...")
    for i in range(len(X) - seq_length + 1):
        # 创建序列
        seq = X[i:i + seq_length]
        label = y[i + seq_length - 1]

        tensor = torch.FloatTensor(seq).unsqueeze(0)

        with torch.no_grad():
            output = model(tensor)
            pred = torch.argmax(output, dim=1).item()

        # 统计
        if pred == label:
            correct += 1

        if pred == 1 and label == 1:
            tp += 1
        elif pred == 1 and label == 0:
            fp += 1
        elif pred == 0 and label == 0:
            tn += 1
        else:
            fn += 1

        if (i + 1) % 1000 == 0:
            print(f"  已测试 {i + 1}/{len(X)}")

    # 计算指标
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print("\n" + "=" * 60)
    print("测试结果")
    print("=" * 60)
    print(f"准确率:  {accuracy:.4f}")
    print(f"精确率:  {precision:.4f}")
    print(f"召回率:  {recall:.4f}")
    print(f"F1分数:  {f1:.4f}")
    print(f"\n混淆矩阵:")
    print(f"  TN: {tn}, FP: {fp}")
    print(f"  FN: {fn}, TP: {tp}")


if __name__ == "__main__":
    test_with_real_data()
