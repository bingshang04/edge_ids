"""
用真实 UNSW-NB15 数据测试模型 - 带漏检分析
"""

import torch
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import json
from src.models.tcn_model import TCN


def load_model():
    """加载训练好的模型"""
    model = TCN(
        input_dim=39,
        num_classes=2,
        num_channels=[128, 256],
        dropout=0.2
    )
    model.load_state_dict(torch.load('../data/models/tcn_model.pth', map_location='cpu'))
    model.eval()
    return model


def analyze_missed_attacks(test_df, missed_indices, feature_cols, y_true, y_pred):
    """深入分析漏检的攻击样本"""
    print("\n" + "=" * 60)
    print("漏检样本深度分析")
    print("=" * 60)

    # 获取漏检样本的原始数据
    missed_df = test_df.iloc[missed_indices].copy()
    missed_df['predicted_label'] = y_pred[missed_indices]

    print(f"\n总漏检数: {len(missed_indices)}")

    # 1. 按攻击类型分析（如果有attack_cat列）
    if 'attack_cat' in missed_df.columns:
        print("\n漏检样本的攻击类型分布:")
        attack_dist = missed_df['attack_cat'].value_counts()
        for attack_type, count in attack_dist.items():
            total_of_type = test_df[test_df['attack_cat'] == attack_type].shape[0]
            miss_rate = count / total_of_type if total_of_type > 0 else 0
            print(f"  {attack_type}: {count}个 (该类型漏检率: {miss_rate:.2%})")

    # 2. 关键特征统计对比（漏检 vs 正常检出）
    print("\n漏检样本 vs 正确检出样本的关键特征对比:")

    # 正确检出的攻击样本
    correct_tp_indices = [i for i, (t, p) in enumerate(zip(y_true, y_pred))
                          if t == 1 and p == 1 and i < len(test_df)]

    if len(correct_tp_indices) > 0:
        correct_tp_df = test_df.iloc[correct_tp_indices]

        key_features = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
                        'sttl', 'dttl', 'sload', 'dload']

        for feat in key_features:
            if feat in missed_df.columns:
                missed_mean = missed_df[feat].mean()
                correct_mean = correct_tp_df[feat].mean()
                print(f"  {feat}:")
                print(f"    漏检样本均值: {missed_mean:.2f}")
                print(f"    正确检出均值: {correct_mean:.2f}")
                print(f"    差异: {abs(missed_mean - correct_mean):.2f}")

    # 3. 保存漏检样本详情
    missed_df.to_csv('data/missed_attacks_analysis.csv', index=False)
    print(f"\n漏检样本详情已保存到: data/missed_attacks_analysis.csv")

    # 4. 输出部分漏检样本示例
    print("\n漏检样本示例 (前5个):")
    print(missed_df[['dur', 'proto', 'service', 'state', 'sbytes', 'dbytes', 'attack_cat']].head())

    return missed_df


def test_with_real_data():
    print("=" * 60)
    print("用真实 UNSW-NB15 数据测试 - 带漏检追踪")
    print("=" * 60)

    # 加载模型
    model = load_model()
    print("模型加载成功")

    print("\n测试数据...")
    test_df = pd.read_csv('../data/raw/UNSW_NB15_testing-set.csv')

    # 选择特征
    feature_cols = [col for col in test_df.columns
                    if col not in ['id', 'proto', 'service', 'state', 'attack_cat', 'label']]

    # 处理缺失值
    X = test_df[feature_cols].fillna(0).values
    y = test_df['label'].values

    # 标准化（⚠注意：应该用训练时的scaler，这里简化处理）
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    print(f"测试样本数: {len(X)}")
    print(f"攻击样本: {y.sum()} ({y.mean():.2%})")

    # 创建序列
    seq_length = 10

    # 记录每个样本的预测结果
    all_predictions = []  # 记录所有预测标签
    all_true_labels = []  # 记录所有真实标签
    sample_indices = []  # 记录对应的原始样本索引

    print("\n开始测试...")
    for i in range(len(X) - seq_length + 1):
        # 创建序列
        seq = X[i:i + seq_length]
        label = y[i + seq_length - 1]
        original_idx = i + seq_length - 1  # 对应原始数据的索引

        tensor = torch.FloatTensor(seq).unsqueeze(0)

        with torch.no_grad():
            output = model(tensor)
            pred = torch.argmax(output, dim=1).item()

        # 记录结果
        all_predictions.append(pred)
        all_true_labels.append(label)
        sample_indices.append(original_idx)

        if (i + 1) % 1000 == 0:
            print(f"  已测试 {i + 1}/{len(X) - seq_length + 1}")

    # 转换为numpy数组方便处理
    all_predictions = np.array(all_predictions)
    all_true_labels = np.array(all_true_labels)
    sample_indices = np.array(sample_indices)

    # 计算混淆矩阵
    tp = np.sum((all_predictions == 1) & (all_true_labels == 1))
    fp = np.sum((all_predictions == 1) & (all_true_labels == 0))
    tn = np.sum((all_predictions == 0) & (all_true_labels == 0))
    fn = np.sum((all_predictions == 0) & (all_true_labels == 1))

    # 找出漏检样本（FN: 真实是攻击，预测为正常）
    missed_mask = (all_true_labels == 1) & (all_predictions == 0)
    missed_indices = sample_indices[missed_mask]

    print(f"\n发现 {len(missed_indices)} 个漏检样本")
    print(f"   原始数据索引: {missed_indices[:10]}...")  # 显示前10个

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

    # 保存漏检信息
    missed_info = {
        'total_missed': int(fn),
        'missed_indices': missed_indices.tolist(),
        'missed_percent': float(fn / (tp + fn) * 100)
    }

    with open('../data/missed_attacks_info.json', 'w') as f:
        json.dump(missed_info, f, indent=2)
    print(f"\n漏检索引已保存到: data/missed_attacks_info.json")

    # 深度分析漏检样本
    if len(missed_indices) > 0:
        analyze_missed_attacks(test_df, missed_indices, feature_cols,
                               all_true_labels, all_predictions)

        # 显示一些具体的漏检样本
        print("\n" + "=" * 60)
        print("具体漏检样本详情")
        print("=" * 60)
        for idx in missed_indices[:3]:  # 显示前3个
            row = test_df.iloc[idx]
            print(f"\n样本索引 {idx}:")
            print(f"  攻击类型: {row.get('attack_cat', 'N/A')}")
            print(f"  协议: {row.get('proto', 'N/A')}, 服务: {row.get('service', 'N/A')}")
            print(f"  持续时间: {row.get('dur', 'N/A')}, 字节数: {row.get('sbytes', 'N/A')}/{row.get('dbytes', 'N/A')}")
            print(f"  关键特征值: rate={row.get('rate', 'N/A'):.2f}, sttl={row.get('sttl', 'N/A')}")


if __name__ == "__main__":
    test_with_real_data()