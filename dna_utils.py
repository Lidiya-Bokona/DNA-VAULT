import zstandard as zstd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

class DNAUtils:
    def __init__(self):
        self.key = get_random_bytes(32)  # AES-256 key
        self.for_synthesis_folder = 'for_synthesis'
        os.makedirs(self.for_synthesis_folder, exist_ok=True)

    def binary_to_nitrogen_bases(self, data):
        base_map = {
            '00': 'A', '01': 'T', '10': 'C', '11': 'G'
        }
        bits = ''.join(f'{byte:08b}' for byte in data)
        return ''.join(base_map[bits[i:i+2]] for i in range(0, len(bits), 2))

    def compress_data(self, data):
        compressor = zstd.ZstdCompressor(level=10)  # Higher compression level
        return compressor.compress(data)

    def encrypt_data(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def process_file(self, file_path, output_filename):
        with open(file_path, 'rb') as f:
            original_data = f.read()

        # Step 1: Convert raw data to nitrogen base encoding
        nitrogen_base_data = self.binary_to_nitrogen_bases(original_data)

        # Step 2: Store the nitrogen base data
        output_path = os.path.join(self.for_synthesis_folder, output_filename)
        with open(output_path, 'w') as f:
            f.write(nitrogen_base_data)

        return output_path  # Return the path for reference

# Example usage
def main():
    dna_utils = DNAUtils()
    test_file = "test.txt"
    test_string = "This is a test file for DNA Vault storage."

    # Create a test file
    with open(test_file, "w", encoding="utf-8") as file:
        file.write(test_string)

    # Process the file and save as nitrogen base file
    output_path = dna_utils.process_file(test_file, "output_nb.txt")
    print(f"File processed and saved to: {output_path}")

if __name__ == "__main__":
    main()
