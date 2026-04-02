"""
UNSW-NB15 数据集训练脚本
"""

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import logging
import os

from src.models.tcn_model import TCN
from src.utils.platform_info import PLATFORM_CONFIG

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_and_preprocess_data():
    """加载和预处理数据"""
    train_path = '../data/raw/UNSW_NB15_training-set.csv'
    test_path = '../data/raw/UNSW_NB15_testing-set.csv'

    logger.info("加载数据...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    logger.info(f"训练集: {train_df.shape}, 测试集: {test_df.shape}")

    # 选择数值特征（排除类别特征和标签）
    feature_cols = [col for col in train_df.columns
                    if col not in ['id', 'proto', 'service', 'state', 'attack_cat', 'label']]

    logger.info(f"特征数量: {len(feature_cols)}")

    # 处理缺失值
    train_df[feature_cols] = train_df[feature_cols].fillna(0)
    test_df[feature_cols] = test_df[feature_cols].fillna(0)

    # 标准化
    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_df[feature_cols])
    X_test = scaler.transform(test_df[feature_cols])

    # 标签（二分类）
    y_train = train_df['label'].values
    y_test = test_df['label'].values

    logger.info(f"攻击样本 - 训练: {y_train.sum()} ({y_train.mean():.2%}), "
                f"测试: {y_test.sum()} ({y_test.mean():.2%})")

    return X_train, X_test, y_train, y_test


def create_sequences(X, y, seq_length=10):
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
    """训练模型"""
    config = PLATFORM_CONFIG
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    logger.info(f"使用设备: {device}")

    # 加载数据
    X_train, X_test, y_train, y_test = load_and_preprocess_data()

    # 创建时序数据
    seq_length = config['sequence_length']
    X_train_seq, y_train_seq = create_sequences(X_train, y_train, seq_length)
    X_test_seq, y_test_seq = create_sequences(X_test, y_test, seq_length)

    logger.info(f"时序数据 - 训练: {X_train_seq.shape}, 测试: {X_test_seq.shape}")

    # 转换为 Tensor
    X_train_tensor = torch.FloatTensor(X_train_seq)
    y_train_tensor = torch.LongTensor(y_train_seq)
    X_test_tensor = torch.FloatTensor(X_test_seq)
    y_test_tensor = torch.LongTensor(y_test_seq)

    # 创建 DataLoader
    batch_size = config['batch_size']
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    test_dataset = TensorDataset(X_test_tensor, y_test_tensor)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=batch_size)

    # 创建模型
    input_dim = X_train.shape[1]
    model = TCN(
        input_dim=input_dim,
        num_classes=2,
        num_channels=[config['hidden_dim'], config['hidden_dim'] * 2],
        dropout=0.2
    ).to(device)

    logger.info(f"模型参数: {model.num_params / 1e6:.2f}M")

    # 损失函数和优化器
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    # 训练
    num_epochs = 5
    best_acc = 0

    for epoch in range(num_epochs):
        # 训练
        model.train()
        train_loss = 0

        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)

            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

            train_loss += loss.item()

        # 验证
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

        logger.info(f"Epoch {epoch + 1}/{num_epochs} - "
                    f"Loss: {train_loss / len(train_loader):.4f}, "
                    f"Acc: {acc:.4f}, P: {prec:.4f}, R: {rec:.4f}, F1: {f1:.4f}")

        # 保存最佳模型
        if acc > best_acc:
            best_acc = acc
            os.makedirs('../data/models', exist_ok=True)
            torch.save(model.state_dict(), '../data/models/tcn_model.pth')
            logger.info(f"  -> 保存最佳模型 (Acc: {acc:.4f})")

    # 最终评估
    logger.info("\n最终评估:")
    cm = confusion_matrix(all_labels, all_preds)
    logger.info(f"混淆矩阵:\n{cm}")

    return model


if __name__ == "__main__":
    train_model()
