import json
import os

from methods.XOR import xor_encrypt, xor_decrypt
from methods.AES import aes_encrypt, aes_decrypt

def encrypt(args):
    print(f"Шифруем {args.input_file} {args.algo} алгоритмом...")

    mode = None
    if args.algo.startswith('aes-'):
        mode = args.algo.replace('aes-', '')

    if args.algo == 'stream':
        encrypted_data, meta = xor_encrypt(args.input_file, args.key, args.iv)
    elif args.algo.startswith('aes-'):
        encrypted_data, meta = aes_encrypt(
            args.input_file, 
            args.key, 
            mode=mode,
            iv=args.iv,
            nonce=args.nonce
        )
    
    with open(args.output_file, 'wb') as f:
        f.write(encrypted_data)
    
    meta_filename = args.output_file + ".meta.json"
    if args.meta:
        meta_filename = args.meta
    
    with open(meta_filename, 'w') as f:
        json.dump(meta, f, indent=2)
    
    print(f"Успешно зашифровано в {args.output_file}")
    print(f"Метаданные сохранены в {meta_filename}")
    if meta.get('iv'):
        print(f"IV: {meta['iv']}")
    if meta.get('nonce'):
        print(f"Nonce: {meta['nonce']}")
    

def decrypt(args):
    print(f"Дешифруем {args.input_file} {args.algo} алгоритмом...")
    
    meta = {}
    if args.meta:
        with open(args.meta, 'r') as f:
            meta = json.load(f)
    else:
        meta_path = args.input_file + ".meta.json"
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                meta = json.load(f)
        else:
            print("Предупреждение: файл метаданных не найден")
    
    if args.algo == 'stream':
        decrypted_data = xor_decrypt(args.input_file, args.key, meta)
    elif args.algo.startswith('aes-'):
        decrypted_data = aes_decrypt(args.input_file, args.key, meta)
    
    from PIL import Image
    img = Image.frombytes(meta['mode'], meta['original_size'], decrypted_data)
    img.save(args.output_file)
    
    print(f"Успешно дешифровано в {args.output_file}")