import os

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

def create_metrics():
    pass

"""
Отделяю блок "запуска" кода
=========================================================================================================
"""


def main():
    create_test_images()
    create_metrics()


if __name__ == "__main__":
    main()