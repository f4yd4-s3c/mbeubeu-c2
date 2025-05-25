import random
import string

def generate_hex_key(length=64):
    hex_chars = string.hexdigits.upper()[:16]  # '0123456789ABCDEF'
    return ''.join(random.choices(hex_chars, k=length))

# Example usage
if __name__ == "__main__":
    print("Random AES-256 key (hex string):")
    print(generate_hex_key())
