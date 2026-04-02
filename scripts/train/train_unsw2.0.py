import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import logging
import os

from src.models.tcn_model import TCN
from src.utils.platform_info import PLATFORM_CONFIG

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_and_preprocess_data():
    """加载和预处理数据（修复 unseen labels + 特征工程）"""
    train_path = '../data/raw/UNSW_NB15_training-set.csv'
    test_path = '../data/raw/UNSW_NB15_testing-set.csv'

    logger.info("加载数据...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    logger.info(f"原始训练集: {train_df.shape}, 测试集: {test_df.shape}")

    # ====================== 特征工程 ======================
    # 1. 基础数值特征
    numeric_cols = [col for col in train_df.columns
                    if col not in ['id', 'proto', 'service', 'state', 'attack_cat', 'label']]

    # 2. 新增衍生特征
    for df in [train_df, test_df]:
        df['byte_ratio'] = df['sbytes'] / (df['dbytes'] + 1e-6)
        df['load_ratio'] = df['sload'] / (df['dload'] + 1e-6)
        df['pkt_ratio'] = df['spkts'] / (df['spkts'] + df['dpkts'] + 1e-6)
        df['dur_rate'] = df['dur'] * df['rate']
        df['ttl_diff'] = df['sttl'] - df['dttl']
        df['avg_pkt_size'] = (df['sbytes'] + df['dbytes']) / (df['spkts'] + df['dpkts'] + 1e-6)

    # 3. 类别特征编码（合并 train + test 再 fit）
    cat_cols = ['proto', 'service', 'state']
    for col in cat_cols:
        # 把训练集和测试集的该列合并，统一 fit LabelEncoder
        combined = pd.concat([train_df[col], test_df[col]], axis=0).fillna('unknown').astype(str)
        le = LabelEncoder()
        le.fit(combined)

        # 转换回训练集和测试集
        train_df[col] = le.transform(train_df[col].fillna('unknown').astype(str))
        test_df[col] = le.transform(test_df[col].fillna('unknown').astype(str))

        logger.info(f"列 {col} 编码完成，类别数: {len(le.classes_)}")

    # 最终特征列表
    feature_cols = numeric_cols + ['byte_ratio', 'load_ratio', 'pkt_ratio',
                                   'dur_rate', 'ttl_diff', 'avg_pkt_size'] + cat_cols

    logger.info(f"最终特征数量: {len(feature_cols)}（含衍生特征）")

    # 处理缺失值
    train_df[feature_cols] = train_df[feature_cols].fillna(0)
    test_df[feature_cols] = test_df[feature_cols].fillna(0)

    # 标准化
    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_df[feature_cols])
    X_test = scaler.transform(test_df[feature_cols])

    # 标签
    y_train = train_df['label'].values
    y_test = test_df['label'].values

    logger.info(f"攻击样本 - 训练: {y_train.sum()} ({y_train.mean():.2%}), "
                f"测试: {y_test.sum()} ({y_test.mean():.2%})")

    return X_train, X_test, y_train, y_test, len(feature_cols)


def create_sequences(X, y, seq_length=12):
    """创建时序序列"""
    sequences = []
    labels = []

    for i in range(len(X) - seq_length + 1):
        seq = X[i:i + seq_length]
        label = y[i + seq_length - 1]
        sequences.append(seq)
        labels.append(label)

    return np.array(sequences), np.array(labels)


def train_model():
    config = PLATFORM_CONFIG
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    logger.info(f"使用设备: {device}")

    # 加载数据
    X_train, X_test, y_train, y_test, input_dim = load_and_preprocess_data()

    # 创建时序数据
    seq_length = config['sequence_length']          # 默认 10，可在 platform_info.py 中修改
    X_train_seq, y_train_seq = create_sequences(X_train, y_train, seq_length)
    X_test_seq, y_test_seq = create_sequences(X_test, y_test, seq_length)

    logger.info(f"时序数据 - 训练: {X_train_seq.shape}, 测试: {X_test_seq.shape}")

    # 转换为 Tensor
    X_train_tensor = torch.FloatTensor(X_train_seq)
    y_train_tensor = torch.LongTensor(y_train_seq)
    X_test_tensor = torch.FloatTensor(X_test_seq)
    y_test_tensor = torch.LongTensor(y_test_seq)

    # DataLoader
    batch_size = config['batch_size']
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    test_dataset = TensorDataset(X_test_tensor, y_test_tensor)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=batch_size)

    # ====================== 模型 ======================
    model = TCN(
        input_dim=input_dim,          # 自动适配新特征数量
        num_classes=2,
        num_channels=[128, 256, 256],  # 优化后架构（已在 tcn_model.py 中更新）
        kernel_size=5,
        dropout=0.3
    ).to(device)

    logger.info(f"模型参数: {model.num_params / 1e6:.2f}M")

    # ====================== 加权损失（关键优化）======================
    class_weights = compute_class_weight(
        class_weight='balanced',
        classes=np.unique(y_train),
        y=y_train
    )
    class_weights = torch.FloatTensor(class_weights).to(device)
    # 重点提升攻击类权重
    class_weights[1] = class_weights[1] * 1.85

    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=0.0005,           #学习率低，更稳定
        weight_decay=5e-5    # 正则化
    )

    # 训练
    num_epochs = 10          # 增加到 10 个 epoch
    best_acc = 0.0
    best_recall = 0.0

    for epoch in range(num_epochs):
        # 训练阶段
        model.train()
        train_loss = 0.0

        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)

            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

            train_loss += loss.item()

        # 验证阶段
        model.eval()
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for batch_x, batch_y in test_loader:
                batch_x = batch_x.to(device)
                outputs = model(batch_x)
                preds = torch.argmax(outputs, dim=1).cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(batch_y.numpy())

        # 计算指标
        acc = accuracy_score(all_labels, all_preds)
        prec = precision_score(all_labels, all_preds, zero_division=0)
        rec = recall_score(all_labels, all_preds, zero_division=0)
        f1 = f1_score(all_labels, all_preds, zero_division=0)

        logger.info(f"Epoch {epoch + 1:2d}/{num_epochs} - "
                    f"Loss: {train_loss / len(train_loader):.4f} | "
                    f"Acc: {acc:.4f} | P: {prec:.4f} | R: {rec:.4f} | F1: {f1:.4f}")

        # 保存最高准确率模型（使用新文件名，防止覆盖旧模型）
        if acc > best_acc or (acc == best_acc and rec > best_recall):
            best_acc = acc
            best_recall = rec
            os.makedirs('../data/models', exist_ok=True)
            save_path = '../data/models/tcn_model2.2.pth'
            torch.save(model.state_dict(), save_path)
            logger.info(f"  → 保存新最佳模型 (Acc: {acc:.4f}, Recall: {rec:.4f}) → {save_path}")

    # 最终评估
    logger.info("\n最终评估:")
    cm = confusion_matrix(all_labels, all_preds)
    logger.info(f"混淆矩阵:\n{cm}")

    logger.info(f"\n优化版模型已保存至: data/models/tcn_model2.1.pth")
    return model


if __name__ == "__main__":
    train_model()