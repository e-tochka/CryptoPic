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
Далее программный код, который отделяю, чтобы симитировать var разделение для изменяемый паарметров
=========================================================================================================
"""
def init():
    global current_dir 
    current_dir = os.path.dirname(os.path.abspath(__file__))
    for folder in ['results/encrypted','results/decrypted', 'results/meta']:
        full_path = os.path.join(current_dir, folder)
        os.makedirs(full_path, exist_ok=True)
        
        gitkeep_file = os.path.join(full_path, '.gitkeep')
        if not os.path.exists(gitkeep_file):
            with open(gitkeep_file, 'w') as f:
                pass
    
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
    cmd = create_command('encrypt', 'imgs/'+img, 'results/encrypted/'+img+'_'+algo+'.bin', algo, key, None, None, 'results/meta/'+img+'_'+algo+'.json')
    execute_cmd(cmd)

def decrypt(img, algo):
    print(f"Дешифруем {img} через {algo} метод...")
    cmd = create_command('decrypt', 'results/encrypted/'+img+'_'+algo+'.bin', 'results/decrypted/'+img+'_'+algo+'.png', algo, key, None, None, 'results/meta/'+img+'_'+algo+'.json')
    execute_cmd(cmd)

def create_test_images():
    for algoritm in algoritms:
        for image in source_images:
            encrypt(image, algoritm)
            decrypt(image, algoritm)


def main():
    init()
    create_test_images()


if __name__ == "__main__":
    main()