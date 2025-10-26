import argparse

def create_parser():
    parser = argparse.ArgumentParser(description='CryptoPic - Image Encryption Tool')
    
    
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'],                                 required=True, help='encrypt or decrypt')
    parser.add_argument('--in',   dest='input_file',                                              required=True, help='input_file')
    parser.add_argument('--out',  dest='output_file',                                             required=True, help='output_file')
    # parser.add_argument('--algo', choices=['stream', 'aes-ecb', 'aes-cbc', 'aes-ctr', 'aes-cfb'], required=True, help='algo')
    # parser.add_argument('--key',                                                                  required=True, help='key')
    # parser.add_argument('--iv',                                                                                  help='iv')
    # parser.add_argument('--nonce',                                                                               help='nonce')
    # parser.add_argument('--meta',                                                                                help='meta')
    
    return parser


def get_args():
    parser = create_parser()
    return parser.parse_args()