import os
import math
import json
from collections import Counter
import statistics
from PIL import Image

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
|￣￣￣￣￣￣￣|
  HELP ME PLS |
|＿＿＿＿＿＿＿|
     ||  (\__/)
     ||  (•ㅅ•)
　＿||ノ ヽ ノ＼＿
`/　`|| ⌒Ｙ⌒ Ｙ　ヽ
( 　(三ヽ人　 /　　 |
|　ﾉ⌒＼ ￣￣ヽ　 ノ
ヽ＿＿＿＞､＿＿_／
　　 ｜( 王 ﾉ〈
　　 /ﾐ`ー―彡


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
        'results/metrics'
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
Отделяю блок "запуска" кода
=========================================================================================================
"""

def main():
    create_test_images()
    create_metrics()

if __name__ == "__main__":
    main()