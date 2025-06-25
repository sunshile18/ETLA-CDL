import os
import glob
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import warnings


def find_csv_files_with_prefix(folder_path, prefix='1'):

    file_pattern = os.path.join(folder_path, f'{prefix}*.csv')
    return [os.path.basename(file) for file in glob.glob(file_pattern)]

def save_confusion_matrix(y_true, y_pred, class_names, file_path, app_name, domain_info):

    cm = confusion_matrix(y_true, y_pred, labels=class_names)
    cm_percent = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    
    plt.figure(figsize=(12, 10))
    sns.heatmap(cm_percent, annot=True, fmt='.2%', cmap='coolwarm',
                xticklabels=class_names, yticklabels=class_names,
                cbar_kws={'shrink': .8}, linewidths=0.5, linecolor='black',
                annot_kws={"size": 12, "weight": "bold"})
    
    plt.title(f'Confusion Matrix for {app_name} - {domain_info}', fontsize=16, weight='bold')
    plt.xlabel('Predicted Labels', fontsize=14)
    plt.ylabel('True Labels', fontsize=14)
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0, va='center')
    
    plt.tight_layout()
    plt.savefig(file_path, dpi=300)
    plt.close()

def extract_app_name(folder_path):

    return os.path.basename(os.path.dirname(folder_path))

def preprocess_data(df):

    if 'loc' not in df.columns:
        raise ValueError("DataFrame 必须包含 'loc' 列。")
    
    X = df.drop(columns='loc')
    y = df['loc']

    if X.isna().any().any() or np.isinf(X).any().any():
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)
    
    return X, y

def ensure_minimum_samples(df, domain_info, min_samples=2):

    class_counts = df['loc'].value_counts()
    rare_classes = class_counts[class_counts < min_samples].index
    if not rare_classes.empty:
        print(f"Domain Info: {domain_info} - 类别样本少于 {min_samples} 的类别: {rare_classes.tolist()}")
        df = df[~df['loc'].isin(rare_classes)]
    return df

def save_test_results(X_test, y_test, y_pred, file_path):

    test_results = X_test.copy()
    test_results['true_labels'] = y_test.values
    test_results['predicted_labels'] = y_pred
    test_results.to_csv(file_path, index=False)


def evaluate_files(folder_path, file_names):

    results = []
    output_csv = os.path.join(folder_path, 'evaluateresults.csv')
    
    app_name = extract_app_name(folder_path)
    
    for file_name in file_names:
        file_path = os.path.join(folder_path, file_name)
        base_name = os.path.splitext(file_name)[0]
        domain_info = base_name.split('_')[1] if '_' in base_name else base_name
        domain_info = domain_info.split('.num')[0]
        
        try:
            df = pd.read_csv(file_path)
            df = ensure_minimum_samples(df, domain_info)
            X, y = preprocess_data(df)
        except Exception as e:
            print(f"处理文件 {file_name} 时出错: {e}")
            continue
        
        try:
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.99, random_state=42, stratify=y)
        except ValueError as e:
            print(f"文件 {file_name} 的训练-测试拆分时出错: {e}")
            continue
        
        class_names = sorted(y.unique())
        missing_classes = set(class_names) - set(y_test.unique())
        if missing_classes:
            print(f"警告: 文件 {file_name} 的测试集中缺少以下类别: {missing_classes}")
            continue
        
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            precision = precision_score(y_test, y_pred, average='weighted', zero_division=1)
            recall = recall_score(y_test, y_pred, average='weighted', zero_division=1)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=1)

            for warning in w:
                if 'Precision is ill-defined' in str(warning.message):
                    print(f"文件 {file_name} 触发了精确度警告: {warning.message}")

        accuracy = accuracy_score(y_test, y_pred)
        
        conf_matrix_path = os.path.join(folder_path, f'2_{file_name}_confusion_matrix.png')
        save_confusion_matrix(y_test, y_pred, class_names, conf_matrix_path, app_name, domain_info)
        
        test_results_path = os.path.join(folder_path, f'2_{file_name}_test_results.csv')
        save_test_results(X_test, y_test, y_pred, test_results_path)
        
        results.append({
            'file_name': file_name,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1
        })
    
    results_df = pd.DataFrame(results)
    results_df.to_csv(output_csv, index=False)

    top_three = results_df.nlargest(3, 'accuracy')
    return top_three[['file_name', 'accuracy']]

data_list = ['hema', 'darunfa','dazhong','baiduditu',
             'meituan','douyin','tengxun','58','transit',
             'foodpanda','yelp','opentable','waze',
             'googlemap','moji','haluo','yonghui','kfc']

#data path
base_path = ""
paths = [f"{base_path}{item}/data/" for item in data_list]

for folder_path in paths:
    print(folder_path)
    file_names = find_csv_files_with_prefix(folder_path)
    top_files = evaluate_files(folder_path, file_names)
    print("准确率最高的前三个文件:")
    print(top_files)
    print("---------------------------------------------")
