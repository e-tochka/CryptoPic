import os
import sys

from encrypt import encrypt
from decrypt import decrypt
from parser import get_args

def main():
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    args = get_args()    
    try:
        if args.mode == 'encrypt':
            encrypt(args)
        elif args.mode == 'decrypt':
            decrypt(args)
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()