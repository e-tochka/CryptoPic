import argparse

def create_parser():
    parser = argparse.ArgumentParser(description='CryptoPic - Image Encryption Tool')
    
    
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'],                                 required=True, help='Режим работы: encrypt или decrypt')
    # parser.add_argument('--in',   dest='input_file',                                              required=True, help='Входной файл (изображение или шифр)')
    # parser.add_argument('--out',  dest='output_file',                                             required=True, help='Выходной файл')
    # parser.add_argument('--algo', choices=['stream', 'aes-ecb', 'aes-cbc', 'aes-ctr', 'aes-cfb'], required=True, help='Алгоритм шифрования')
    # parser.add_argument('--key',                                                                  required=True, help='Ключ шифрования')
    # parser.add_argument('--iv',                                                                                  help='IV в hex формате (для CBC)')
    # parser.add_argument('--nonce',                                                                               help='Nonce в hex формате (для CTR)')
    # parser.add_argument('--meta',                                                                                help='Файл с метаданными для дешифрования')
    
    return parser

def get_args():
    parser = create_parser()
    return parser.parse_args()