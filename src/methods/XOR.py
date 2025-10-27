from PIL import Image
import os

class RC4:
    def __init__(self, key, iv):
        self.S = list(range(256))
        self.i = 0
        self.j = 0
        self._key_scheduling(key, iv)
    
    def _key_scheduling(self, key, iv):
        combined_key = key + iv
        j = 0
        
        for i in range(256):
            j = (j + self.S[i] + combined_key[i % len(combined_key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        
        j = 0
        for i in range(256):
            j = (j + self.S[i] + combined_key[(i + 128) % len(combined_key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    
    def generate_keystream(self, length):
        keystream = bytearray()
        for _ in range(length):
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            
            k = self.S[(self.S[self.i] + self.S[self.j] + self.S[(self.i * self.j) % 256]) % 256]
            keystream.append(k)
        
        return bytes(keystream)


def initialize_rc4_key(key_string):
    combined = key_string.encode('utf-8') 
    if len(combined) < 32:
        combined = simple_hash(combined, 32)  
    
    return combined

def simple_hash(data, output_length=32, return_hex=False):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    result = bytearray(output_length)

    for i in range(output_length):
        result[i] = (data[i % len(data)] + i * 37) & 0xFF
    
    for round in range(5):
        for i in range(output_length):
            result[i] ^= result[(i + 11) % output_length]
            result[i] = (result[i] * 167 + 113) & 0xFF
    
    if return_hex:
        return result.hex()  
    else:
        return bytes(result)  

def rc4_encrypt_decrypt(data, key, iv):
    rc4 = RC4(key, iv)
    keystream = rc4.generate_keystream(len(data))
    
    return bytes([data[i] ^ keystream[i] for i in range(len(data))])

def xor_encrypt(image_path, key_string, iv=None):
    img = Image.open(image_path)
    img_bytes = img.tobytes()
    
    if iv is None:
        iv = os.urandom(16) 
        print(f" Сгенерирован случайный IV: {iv.hex()}")
    else:
        print(f" Используется предоставленный IV: {iv.hex()}")
    
    key_bytes = initialize_rc4_key(key_string)
    
    encrypted_bytes = rc4_encrypt_decrypt(img_bytes, key_bytes, iv)
    
    meta = {
        "algorithm": "stream-rc4-custom",
        "original_size": img.size,
        "mode": img.mode,
        "iv": iv.hex(),
        "original_filename": os.path.basename(image_path),
        "key_hash": simple_hash(key_string, 16, return_hex=True)  
    }
    
    return encrypted_bytes, meta

def xor_decrypt(input_path, key_string, meta):
    with open(input_path, 'rb') as f:
        encrypted_bytes = f.read()
    
    iv_hex = meta.get('iv')
    if not iv_hex:
        raise ValueError("IV не найден в метаданных!")
    
    iv = bytes.fromhex(iv_hex)
    
    expected_hash = meta.get('key_hash')
    if expected_hash:
        actual_hash = simple_hash(key_string, 16, return_hex=True)
        if actual_hash != expected_hash:
            print("Проблемки с хэшом ключа")
    
    key_bytes = initialize_rc4_key(key_string)
    
    decrypted_bytes = rc4_encrypt_decrypt(encrypted_bytes, key_bytes, iv)
    
    return decrypted_bytes