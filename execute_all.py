import os
import math
import json
from collections import Counter
import statistics
from PIL import Image
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import rcParams

# Настройка шрифтов для русского языка
rcParams['font.family'] = 'DejaVu Sans'
rcParams['font.size'] = 10

source_images = [
    'checkerboard.png', 
    'gradient.png', 
    'noise_texture.png', 
    'my_image.png'
]

algoritms = [
    'stream', 
    'aes-ecb', 
    'aes-cbc', 
    'aes-ctr'
]

key = 'qwerty'

"""
Далее программный код, который отделяю, чтобы симитировать var разделение для изменяемый паарметров
=========================================================================================================
"""
def init():
    global current_dir 
    current_dir = os.path.dirname(os.path.abspath(__file__))
    folders = [
        'results/encrypted',
        'results/decrypted', 
        'results/meta', 
        'results/metrics',
        'results/graphs'
    ]
    for folder in folders:
        full_path = os.path.join(current_dir, folder)
        os.makedirs(full_path, exist_ok=True)
    print("Успешная инициализация")


def execute_cmd(cmd):
    return os.system(f"cd {current_dir} && {cmd}")
 
def create_command(_mode, _in, _out, _algo, _key, _iv, _nonce, _meta):
    cmd = f"python src/main.py --mode {_mode} --in {_in} --out {_out} --algo {_algo} --key {_key}"
    if _iv:
        cmd += f" --iv {_iv}"
    if _nonce:
        cmd += f" --nonce {_nonce}"
    if _meta:
        cmd += f" --meta {_meta}"   
    return cmd

def encrypt(img, algo):
    print(f"Шифруем {img} через {algo} метод...")
    cmd = create_command('encrypt', 'imgs/'+img, 'results/encrypted/'+img+'.'+algo+'.bin', algo, key, None, None, 'results/meta/'+img+'.'+algo+'.json')
    execute_cmd(cmd)

def decrypt(img, algo):
    print(f"Дешифруем {img} через {algo} метод...")
    cmd = create_command('decrypt', 'results/encrypted/'+img+'.'+algo+'.bin', 'results/decrypted/'+img+'.'+algo+'.png', algo, key, None, None, 'results/meta/'+img+'.'+algo+'.json')
    execute_cmd(cmd)

def create_test_images():
    init()
    for algoritm in algoritms:
        for image in source_images:
            print(f"\n=====({image} by {algoritm})=====")
            encrypt(image, algoritm)
            decrypt(image, algoritm)

"""
Отделяю блок для метрик
=========================================================================================================
"""

def calculate_entropy(data_bytes: bytes) -> float:
    if not data_bytes:
        return 0.0
    byte_counts = Counter(data_bytes)
    total_bytes = len(data_bytes)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy

def calculate_correlation(data_bytes: bytes) -> float:
    if len(data_bytes) < 2:
        return 0.0
    correlations = []
    for i in range(len(data_bytes) - 1):
        correlations.append((data_bytes[i], data_bytes[i + 1]))
    
    x_vals = [p[0] for p in correlations]
    y_vals = [p[1] for p in correlations]
    
    mean_x = statistics.mean(x_vals)
    mean_y = statistics.mean(y_vals)
    
    covariance = sum((x - mean_x) * (y - mean_y) for x, y in correlations)
    variance_x = sum((x - mean_x) ** 2 for x in x_vals)
    variance_y = sum((y - mean_y) ** 2 for y in y_vals)
    
    if variance_x == 0 or variance_y == 0:
        return 0.0
    
    return covariance / math.sqrt(variance_x * variance_y)

def calculate_npcr_uaci(bytes1: bytes, bytes2: bytes):
    min_len = min(len(bytes1), len(bytes2))
    bytes1 = bytes1[:min_len]
    bytes2 = bytes2[:min_len]
    
    if min_len == 0:
        return 0.0, 0.0
    
    changed_bytes = sum(1 for i in range(min_len) if bytes1[i] != bytes2[i])
    total_difference = sum(abs(bytes1[i] - bytes2[i]) for i in range(min_len))
    
    npcr = (changed_bytes / min_len) * 100
    uaci = (total_difference / (min_len * 255)) * 100
    
    return npcr, uaci

def analyze_byte_distribution(data_bytes: bytes):
    if not data_bytes:
        return {"unique_bytes": 0, "uniformity_score": 0}
    
    byte_counts = Counter(data_bytes)
    total_bytes = len(data_bytes)
    expected_per_byte = total_bytes / 256
    
    deviations = [abs(byte_counts.get(i, 0) - expected_per_byte) for i in range(256)]
    avg_deviation = sum(deviations) / len(deviations)
    
    uniformity_score = (1 - (avg_deviation / expected_per_byte)) * 100 if expected_per_byte > 0 else 0
    
    return {
        "unique_bytes": len(byte_counts),
        "total_bytes": total_bytes,
        "uniformity_score": uniformity_score
    }

def analyze_encryption_quality(original_img: str, encrypted_bin: str, algo: str):
    try:
        img = Image.open(original_img)
        original_bytes = img.tobytes()

        with open(encrypted_bin, 'rb') as f:
            encrypted_bytes = f.read()
        
        original_entropy = calculate_entropy(original_bytes)
        encrypted_entropy = calculate_entropy(encrypted_bytes)
        
        original_correlation = calculate_correlation(original_bytes)
        encrypted_correlation = calculate_correlation(encrypted_bytes)
        
        npcr, uaci = calculate_npcr_uaci(original_bytes, encrypted_bytes)
        
        original_distribution = analyze_byte_distribution(original_bytes)
        encrypted_distribution = analyze_byte_distribution(encrypted_bytes)
        
        metrics = {
            "algorithm": algo,
            "image": os.path.basename(original_img),
            "entropy": {
                "original": original_entropy,
                "encrypted": encrypted_entropy,
                "improvement": encrypted_entropy - original_entropy
            },
            "correlation": {
                "original": original_correlation,
                "encrypted": encrypted_correlation,
                "reduction": original_correlation - encrypted_correlation
            },
            "npcr_uaci": {
                "npcr": npcr,
                "uaci": uaci
            },
            "byte_distribution": {
                "original": original_distribution,
                "encrypted": encrypted_distribution
            },
            "file_sizes": {
                "original": len(original_bytes),
                "encrypted": len(encrypted_bytes)
            }
        }
        
        return metrics
        
    except Exception as e:
        print(f"Ошибка анализа {original_img}: {e}")
        return None

def save_metrics(metrics_data, filename):
    metrics_file = os.path.join(current_dir, 'results/metrics', filename)
    with open(metrics_file, 'w', encoding='utf-8') as f:
        json.dump(metrics_data, f, indent=2, ensure_ascii=False)
    print(f"Метрики сохранены: {metrics_file}")

def create_metrics():
    print("\n" + "="*50)
    print("ВЫЧИСЛЕНИЕ МЕТРИК КАЧЕСТВА ШИФРОВАНИЯ")
    print("="*50)
    
    all_metrics = []
    
    for algo in algoritms:
        for image in source_images:
            original_img = os.path.join(current_dir, 'imgs', image)
            encrypted_bin = os.path.join(current_dir, 'results/encrypted', f"{image}.{algo}.bin")
            
            if os.path.exists(original_img) and os.path.exists(encrypted_bin):
                print(f"Анализ: {image} ({algo})")
                metrics = analyze_encryption_quality(original_img, encrypted_bin, algo)
                
                if metrics:
                    all_metrics.append(metrics)
                    
                    individual_filename = f"{image}.{algo}.json"
                    save_metrics(metrics, individual_filename)
                    
                    entropy_imp = metrics["entropy"]["improvement"]
                    npcr = metrics["npcr_uaci"]["npcr"]
                    print(f"  Энтропия: +{entropy_imp:.3f}, NPCR: {npcr:.2f}%")
    
    if all_metrics:
        summary_filename = "encryption_quality_summary.json"
        save_metrics(all_metrics, summary_filename)
        
        print("\n" + "="*50)
        print("ИТОГОВАЯ СТАТИСТИКА:")
        for algo in algoritms:
            algo_metrics = [m for m in all_metrics if m["algorithm"] == algo]
            if algo_metrics:
                avg_entropy = sum(m["entropy"]["encrypted"] for m in algo_metrics) / len(algo_metrics)
                avg_npcr = sum(m["npcr_uaci"]["npcr"] for m in algo_metrics) / len(algo_metrics)
                print(f"  {algo:8}: энтропия {avg_entropy:.3f}, NPCR {avg_npcr:.2f}%")

"""
Блок генерации графиков (изображений)
=========================================================================================================
"""

def create_graphs():
    """Создание графиков для визуализации результатов"""
    print("\n" + "="*50)
    print("ГЕНЕРАЦИЯ ГРАФИКОВ")
    print("="*50)
    
    # Загружаем сохраненные метрики
    summary_file = os.path.join(current_dir, 'results/metrics/encryption_quality_summary.json')
    if not os.path.exists(summary_file):
        print("Файл с метриками не найден! Сначала запустите create_metrics()")
        return
    
    with open(summary_file, 'r', encoding='utf-8') as f:
        all_metrics = json.load(f)
    
    # Создаем графики
    create_entropy_comparison_plot(all_metrics)
    create_npcr_comparison_plot(all_metrics)
    create_correlation_comparison_plot(all_metrics)
    create_uniformity_comparison_plot(all_metrics)
    create_algorithm_radar_plot(all_metrics)
    create_image_comparison_heatmap(all_metrics)
    
    print("Все графики сохранены в results/graphs/")

def create_entropy_comparison_plot(all_metrics):
    """График сравнения энтропии по алгоритмам"""
    plt.figure(figsize=(12, 8))
    
    # Группируем данные по алгоритмам
    algo_data = {}
    for metric in all_metrics:
        algo = metric['algorithm']
        if algo not in algo_data:
            algo_data[algo] = []
        algo_data[algo].append(metric['entropy']['encrypted'])
    
    # Создаем boxplot
    algorithms = list(algo_data.keys())
    data_values = [algo_data[algo] for algo in algorithms]
    
    box_plot = plt.boxplot(data_values, labels=algorithms, patch_artist=True)
    
    # Раскрашиваем boxplot
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
    for patch, color in zip(box_plot['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    # Добавляем идеальную линию
    plt.axhline(y=8.0, color='red', linestyle='--', linewidth=2, 
                label='Идеальная энтропия (8.0)')
    
    plt.title('Сравнение энтропии зашифрованных данных по алгоритмам', fontsize=14, fontweight='bold')
    plt.ylabel('Энтропия Шеннона (биты)', fontsize=12)
    plt.xlabel('Алгоритмы шифрования', fontsize=12)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Сохраняем график
    plt.savefig(os.path.join(current_dir, 'results/graphs/entropy_comparison.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ График энтропии сохранен")

def create_npcr_comparison_plot(all_metrics):
    """График сравнения NPCR по алгоритмам"""
    plt.figure(figsize=(12, 8))
    
    algo_data = {}
    for metric in all_metrics:
        algo = metric['algorithm']
        if algo not in algo_data:
            algo_data[algo] = []
        algo_data[algo].append(metric['npcr_uaci']['npcr'])
    
    algorithms = list(algo_data.keys())
    data_values = [algo_data[algo] for algo in algorithms]
    
    box_plot = plt.boxplot(data_values, labels=algorithms, patch_artist=True)
    
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
    for patch, color in zip(box_plot['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    plt.axhline(y=99.6, color='red', linestyle='--', linewidth=2, 
                label='Идеальный NPCR (99.6%)')
    
    plt.title('Сравнение NPCR по алгоритмам шифрования', fontsize=14, fontweight='bold')
    plt.ylabel('NPCR (%)', fontsize=12)
    plt.xlabel('Алгоритмы шифрования', fontsize=12)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    plt.savefig(os.path.join(current_dir, 'results/graphs/npcr_comparison.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ График NPCR сохранен")

def create_correlation_comparison_plot(all_metrics):
    """График сравнения корреляции по алгоритмам"""
    plt.figure(figsize=(12, 8))
    
    algo_data = {}
    for metric in all_metrics:
        algo = metric['algorithm']
        if algo not in algo_data:
            algo_data[algo] = []
        algo_data[algo].append(metric['correlation']['encrypted'])
    
    algorithms = list(algo_data.keys())
    data_values = [algo_data[algo] for algo in algorithms]
    
    box_plot = plt.boxplot(data_values, labels=algorithms, patch_artist=True)
    
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
    for patch, color in zip(box_plot['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    plt.axhline(y=0.0, color='red', linestyle='--', linewidth=2, 
                label='Идеальная корреляция (0.0)')
    
    plt.title('Сравнение корреляции зашифрованных данных', fontsize=14, fontweight='bold')
    plt.ylabel('Корреляция соседних байтов', fontsize=12)
    plt.xlabel('Алгоритмы шифрования', fontsize=12)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    plt.savefig(os.path.join(current_dir, 'results/graphs/correlation_comparison.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ График корреляции сохранен")

def create_uniformity_comparison_plot(all_metrics):
    """График сравнения равномерности распределения байтов"""
    plt.figure(figsize=(12, 8))
    
    algo_data = {}
    for metric in all_metrics:
        algo = metric['algorithm']
        if algo not in algo_data:
            algo_data[algo] = []
        uniformity = metric['byte_distribution']['encrypted']['uniformity_score']
        algo_data[algo].append(uniformity)
    
    algorithms = list(algo_data.keys())
    data_values = [algo_data[algo] for algo in algorithms]
    
    box_plot = plt.boxplot(data_values, labels=algorithms, patch_artist=True)
    
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
    for patch, color in zip(box_plot['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    plt.axhline(y=100.0, color='red', linestyle='--', linewidth=2, 
                label='Идеальная равномерность (100%)')
    
    plt.title('Сравнение равномерности распределения байтов', fontsize=14, fontweight='bold')
    plt.ylabel('Равномерность распределения (%)', fontsize=12)
    plt.xlabel('Алгоритмы шифрования', fontsize=12)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    plt.savefig(os.path.join(current_dir, 'results/graphs/uniformity_comparison.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ График равномерности сохранен")

def create_algorithm_radar_plot(all_metrics):
    """Радарная диаграмма для сравнения алгоритмов"""
    # Вычисляем средние значения для каждого алгоритма
    algo_stats = {}
    for algo in algoritms:
        algo_metrics = [m for m in all_metrics if m['algorithm'] == algo]
        if algo_metrics:
            algo_stats[algo] = {
                'entropy': np.mean([m['entropy']['encrypted'] for m in algo_metrics]) / 8.0 * 100,  # нормализуем к 100%
                'npcr': np.mean([m['npcr_uaci']['npcr'] for m in algo_metrics]),
                'uniformity': np.mean([m['byte_distribution']['encrypted']['uniformity_score'] for m in algo_metrics]),
                'correlation_reduction': np.mean([abs(m['correlation']['reduction']) for m in algo_metrics]) * 100
            }
    
    if not algo_stats:
        return
    
    # Подготовка данных для радарной диаграммы
    categories = ['Энтропия', 'NPCR', 'Равномерность', 'Снижение\nкорреляции']
    N = len(categories)
    
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]  # Замыкаем круг
    
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))
    
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
    
    for i, (algo, stats) in enumerate(algo_stats.items()):
        values = [
            stats['entropy'],
            stats['npcr'],
            stats['uniformity'],
            stats['correlation_reduction']
        ]
        values += values[:1]  # Замыкаем круг
        
        ax.plot(angles, values, 'o-', linewidth=2, label=algo, color=colors[i])
        ax.fill(angles, values, alpha=0.1, color=colors[i])
    
    # Настройка осей
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories)
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(['20%', '40%', '60%', '80%', '100%'])
    
    plt.title('Сравнительная характеристика алгоритмов шифрования', 
              size=14, fontweight='bold', pad=20)
    plt.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0))
    plt.tight_layout()
    
    plt.savefig(os.path.join(current_dir, 'results/graphs/algorithm_radar.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ Радарная диаграмма сохранена")

def create_image_comparison_heatmap(all_metrics):
    """Тепловая карта сравнения алгоритмов по изображениям"""
    # Создаем матрицу для тепловой карты (изображения × алгоритмы)
    images = sorted(list(set(m['image'] for m in all_metrics)))
    algorithms = sorted(list(set(m['algorithm'] for m in all_metrics)))
    
    # Создаем матрицу значений NPCR
    npcr_matrix = np.zeros((len(images), len(algorithms)))
    
    for i, image in enumerate(images):
        for j, algo in enumerate(algorithms):
            # Ищем соответствующую метрику
            metric = next((m for m in all_metrics 
                          if m['image'] == image and m['algorithm'] == algo), None)
            if metric:
                npcr_matrix[i, j] = metric['npcr_uaci']['npcr']
    
    # Создаем тепловую карту
    plt.figure(figsize=(10, 8))
    im = plt.imshow(npcr_matrix, cmap='RdYlGn', aspect='auto', vmin=99, vmax=100)
    
    # Добавляем подписи
    plt.xticks(range(len(algorithms)), algorithms, rotation=45)
    plt.yticks(range(len(images)), images)
    plt.xlabel('Алгоритмы шифрования')
    plt.ylabel('Изображения')
    plt.title('NPCR по изображениям и алгоритмам (%)', fontsize=14, fontweight='bold')
    
    # Добавляем значения в ячейки
    for i in range(len(images)):
        for j in range(len(algorithms)):
            text = plt.text(j, i, f'{npcr_matrix[i, j]:.1f}%',
                           ha="center", va="center", color="black", fontweight='bold')
    
    # Добавляем цветовую шкалу
    plt.colorbar(im, label='NPCR (%)')
    plt.tight_layout()
    
    plt.savefig(os.path.join(current_dir, 'results/graphs/npcr_heatmap.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    print("✓ Тепловая карта NPCR сохранена")

"""
Генерация отчёта
=========================================================================================================
"""

def create_report():
    retort_text = """# Полученные графики:

![1lab-1](results/graphs/algorithm_radar.png)
![1lab-2](results/graphs/npcr_heatmap.png)
![1lab-3](results/graphs/correlation_comparison.png)
![1lab-4](results/graphs/npcr_comparison.png)
![1lab-5](results/graphs/entropy_comparison.png)
![1lab-6](results/graphs/uniformity_comparison.png)"""
    report_path = os.path.join(current_dir, 'report.md')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(retort_text)
    print(f"Файл отчёта создан: {report_path}")

"""
Отделяю блок "запуска" кода
=========================================================================================================
"""

def main():
    create_test_images()
    create_metrics()
    create_graphs()
    create_report()

if __name__ == "__main__":
    main()