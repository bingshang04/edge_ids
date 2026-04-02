"""
UNSW-NB15 数据集训练脚本 - 【优化版 4.0】
新增功能：
1. 保存 scaler（StandardScaler）
2. 保存三个 LabelEncoder（proto, service, state）
3. 保存路径统一放在 data/models/ 目录下
"""

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
import joblib  # 新增：用于保存 scaler 和 LabelEncoder

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
    numeric_cols = [col for col in train_df.columns
                    if col not in ['id', 'proto', 'service', 'state', 'attack_cat', 'label']]

    # 衍生特征
    for df in [train_df, test_df]:
        df['byte_ratio'] = df['sbytes'] / (df['dbytes'] + 1e-6)
        df['load_ratio'] = df['sload'] / (df['dload'] + 1e-6)
        df['pkt_ratio'] = df['spkts'] / (df['spkts'] + df['dpkts'] + 1e-6)
        df['dur_rate'] = df['dur'] * df['rate']
        df['ttl_diff'] = df['sttl'] - df['dttl']
        df['avg_pkt_size'] = (df['sbytes'] + df['dbytes']) / (df['spkts'] + df['dpkts'] + 1e-6)

    # ====================== LabelEncoder 处理（关键：保存用） ======================
    cat_cols = ['proto', 'service', 'state']
    label_encoders = {}  # 用于后续保存

    for col in cat_cols:
        combined = pd.concat([train_df[col], test_df[col]], axis=0).fillna('unknown').astype(str)
        le = LabelEncoder()
        le.fit(combined)

        train_df[col] = le.transform(train_df[col].fillna('unknown').astype(str))
        test_df[col] = le.transform(test_df[col].fillna('unknown').astype(str))

        label_encoders[col] = le  # 保存 LabelEncoder 对象
        logger.info(f"列 {col} 编码完成，类别数: {len(le.classes_)}")

    # 最终特征列表
    feature_cols = numeric_cols + ['byte_ratio', 'load_ratio', 'pkt_ratio',
                                   'dur_rate', 'ttl_diff', 'avg_pkt_size'] + cat_cols

    logger.info(f"最终特征数量: {len(feature_cols)}（含衍生特征）")

    # 处理缺失值
    train_df[feature_cols] = train_df[feature_cols].fillna(0)
    test_df[feature_cols] = test_df[feature_cols].fillna(0)

    # ====================== 标准化 ======================
    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_df[feature_cols])
    X_test = scaler.transform(test_df[feature_cols])

    y_train = train_df['label'].values
    y_test = test_df['label'].values

    logger.info(f"攻击样本 - 训练: {y_train.sum()} ({y_train.mean():.2%}), "
                f"测试: {y_test.sum()} ({y_test.mean():.2%})")

    return X_train, X_test, y_train, y_test, len(feature_cols), scaler, label_encoders


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
    """训练优化版模型"""
    config = PLATFORM_CONFIG
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    logger.info(f"使用设备: {device}")

    # 加载数据（返回 scaler 和 label_encoders）
    X_train, X_test, y_train, y_test, input_dim, scaler, label_encoders = load_and_preprocess_data()

    # 创建时序数据
    seq_length = 10
    X_train_seq, y_train_seq = create_sequences(X_train, y_train, seq_length)
    X_test_seq, y_test_seq = create_sequences(X_test, y_test, seq_length)

    logger.info(f"时序数据 - 训练: {X_train_seq.shape}, 测试: {X_test_seq.shape}")

    # 转换为 Tensor
    X_train_tensor = torch.FloatTensor(X_train_seq)
    y_train_tensor = torch.LongTensor(y_train_seq)
    X_test_tensor = torch.FloatTensor(X_test_seq)
    y_test_tensor = torch.LongTensor(y_test_seq)

    train_loader = DataLoader(TensorDataset(X_train_tensor, y_train_tensor),
                              batch_size=config['batch_size'], shuffle=True)
    test_loader = DataLoader(TensorDataset(X_test_tensor, y_test_tensor),
                             batch_size=config['batch_size'])

    # 模型
    model = TCN(
        input_dim=input_dim,
        num_classes=2,
        num_channels=[128, 256, 256],
        kernel_size=5,
        dropout=0.3
    ).to(device)

    logger.info(f"模型参数: {model.num_params / 1e6:.2f}M")

    # 加权损失
    class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
    class_weights = torch.FloatTensor(class_weights).to(device)
    class_weights[1] = class_weights[1] * 1.8

    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.0005, weight_decay=5e-5)

    # 训练
    num_epochs = 10
    best_acc = 0.0
    best_recall = 0.0

    for epoch in range(num_epochs):
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

        acc = accuracy_score(all_labels, all_preds)
        prec = precision_score(all_labels, all_preds, zero_division=0)
        rec = recall_score(all_labels, all_preds, zero_division=0)
        f1 = f1_score(all_labels, all_preds, zero_division=0)

        logger.info(f"Epoch {epoch + 1:2d}/{num_epochs} - "
                    f"Loss: {train_loss / len(train_loader):.4f} | "
                    f"Acc: {acc:.4f} | P: {prec:.4f} | R: {rec:.4f} | F1: {f1:.4f}")

        if acc > best_acc or (acc == best_acc and rec > best_recall):
            best_acc = acc
            best_recall = rec
            os.makedirs('../data/models', exist_ok=True)
            save_path = '../data/models/tcn_model_3.0.pth'
            torch.save(model.state_dict(), save_path)
            logger.info(f"  → 保存最佳模型 → {save_path}")

    # ====================== 保存预处理器（关键新增） ======================
    os.makedirs('../data/models', exist_ok=True)

    # 保存 scaler
    joblib.dump(scaler, '../data/models/unsw_scaler3.0.joblib')
    logger.info("Scaler 已保存 → data/models/unsw_scaler3.0.joblib")

    # 保存 LabelEncoders
    for col, le in label_encoders.items():
        joblib.dump(le, f'data/models/le_{col}.joblib')
        logger.info(f"LabelEncoder ({col}) 已保存 → data/models/le_{col}.joblib")

    logger.info("\n训练完成！最佳模型和预处理器已保存。")
    return model


if __name__ == "__main__":
    train_model()