import hashlib
import os
import sys
from PIL import Image
class ImageCipher:
    def __init__(self, secret_key, num_rounds=16):
        self.num_rounds = num_rounds
        self.block_size = 16
        self.half_block = self.block_size // 2
        self.round_keys = self._make_round_keys(secret_key)
    
    def _make_round_keys(self, secret_key):
        key_hash = hashlib.sha256(secret_key.encode()).digest()
        keys_list = []
        for i in range(self.num_rounds):
            key_data = key_hash + i.to_bytes(4, 'big')
            new_key = hashlib.sha256(key_data).digest()[:self.half_block]
            keys_list.append(new_key)
        return keys_list

    def _feistel_function(self, data_block, round_key):
        data_num = int.from_bytes(data_block, 'big')
        key_num = int.from_bytes(round_key, 'big')
        mixed = data_num ^ key_num
        bit_count = self.half_block * 8
        rotated = ((mixed << 3) & (2**bit_count - 1)) | (mixed >> (bit_count - 3))
        return rotated.to_bytes(self.half_block, 'big')
    
    def _process_block(self, data_block, keys):
        left_part = data_block[:self.half_block]
        right_part = data_block[self.half_block:]
        
        for key in keys:
            temp = left_part
            left_part = right_part
            right_mixed = self._feistel_function(right_part, key)
            right_part = bytes(a ^ b for a, b in zip(temp, right_mixed))
        
        return right_part + left_part
    
    def encrypt_data(self, input_data):
        padded_data = self._add_padding(input_data)
        encrypted_blocks = []
        
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i+self.block_size]
            if len(block) < self.block_size:
                block = block.ljust(self.block_size, b'\x00')
            encrypted_block = self._process_block(block, self.round_keys)
            encrypted_blocks.append(encrypted_block)
        
        return b''.join(encrypted_blocks)
    
    def _add_padding(self, data):
        padding_size = self.block_size - (len(data) % self.block_size)
        if padding_size == 0:
            padding_size = self.block_size
        return data + bytes([padding_size] * padding_size)

def get_image_bytes(img_path):
    try:
        with Image.open(img_path) as img:
            if img.mode != 'RGB':
                img = img.convert('RGB')
            pixel_bytes = img.tobytes()
            img_size = img.size
            img_mode = img.mode
            return pixel_bytes, img_size, img_mode
    except Exception as e:
        raise RuntimeError(f"Could not read image: {e}")

def create_image_package(pixel_data, dimensions, color_mode):
    width, height = dimensions
    mode_bytes = color_mode.encode('utf-8')
    if len(mode_bytes) > 255:
        raise ValueError("Color mode name too long")
    
    header_data = (width.to_bytes(4, 'big') + 
                  height.to_bytes(4, 'big') + 
                  len(mode_bytes).to_bytes(1, 'big') + 
                  mode_bytes)
    
    return header_data + pixel_data

def strip_quotes(text):
    return text.strip().strip('"').strip("'")

def encrypt_image_file(source_path, target_path, password, rounds_count=16):
    print("Starting image encryption...")
    print(f"Source: {source_path}")
    print(f"Target: {target_path}")
    print(f"Rounds: {rounds_count}")
    
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source file missing: {source_path}")
    
    try:
        print("Reading image file...")
        pixels, size, mode = get_image_bytes(source_path)
        print(f"Image details: {size[0]}x{size[1]}, {mode} mode")
        
        print("Preparing image data...")
        image_package = create_image_package(pixels, size, mode)
        print(f"Data size: {len(image_package)} bytes")
        
        print("Encrypting...")
        crypto = ImageCipher(password, rounds_count)
        encrypted_bytes = crypto.encrypt_data(image_package)
        print(f"Encrypted size: {len(encrypted_bytes)} bytes")
        
        print("Saving encrypted file...")
        with open(target_path, 'wb') as out_file:
            out_file.write(encrypted_bytes)
        
        print("Encryption successful!")
        print(f"Output file: {target_path}")
        print(f"Keep your password safe: '{password}'")
        
    except Exception as e:
        print(f"Encryption failed: {e}")
        raise

def run_command_line():
    import argparse
    parser = argparse.ArgumentParser(description='Image file encryption tool')
    parser.add_argument('source', help='Source image file path')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-k', '--key', required=True, help='Encryption password')
    parser.add_argument('-r', '--rounds', type=int, default=16, 
                       help='Encryption rounds (default: 16)')
    
    args = parser.parse_args()
    
    clean_source = strip_quotes(args.source)
    
    if not args.output:
        base_name = os.path.splitext(clean_source)[0]
        args.output = base_name + "_encrypted.dat"
    else:
        args.output = strip_quotes(args.output)
    
    try:
        encrypt_image_file(clean_source, args.output, args.key, args.rounds)
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

def main():
    if len(sys.argv) > 1:
        sys.exit(run_command_line())
    
    print("Image Encryption Tool")
    print("=" * 50)
    
    while True:
        try:
            source_file = input("Image file path: ").strip()
            source_file = strip_quotes(source_file)
            
            if not source_file:
                print("Please provide a file path")
                continue
                
            if not os.path.exists(source_file):
                print(f"File not found: {source_file}")
                continue
                
            break
        except KeyboardInterrupt:
            print("\nCancelled")
            return
        except Exception as e:
            print(f"Error: {e}")
    
    crypto_key = input("Encryption password: ").strip()
    if not crypto_key:
        print("Password cannot be empty")
        return
    
    rounds_input = input("Rounds [16]: ").strip()
    try:
        rounds_count = int(rounds_input) if rounds_input else 16
    except ValueError:
        print("Invalid rounds, using default 16")
        rounds_count = 16
    
    output_file = input("Output file [auto]: ").strip()
    output_file = strip_quotes(output_file)
    if not output_file:
        base_name = os.path.splitext(source_file)[0]
        output_file = base_name + "_encrypted.dat"
    
    try:
        encrypt_image_file(source_file, output_file, crypto_key, rounds_count)
    except Exception as e:
        print(f"Operation failed: {e}")

if __name__ == "__main__":
    main()
