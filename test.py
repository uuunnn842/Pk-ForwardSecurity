import hashlib
import random
import os
from ecdsa import SECP256k1, SigningKey
import time
from Crypto.Cipher import AES
from fuzzy_extractor import FuzzyExtractor
# Define the number of test times
TEST_TIMES = 10000  # Default to test 10000 times

# SHA-256 related functions
def calculate_sha256_time(data):
    sha256 = hashlib.sha256()
    start_time = time.time()
    sha256.update(data)
    sha256.hexdigest()#hash value
    end_time = time.time()
    return end_time - start_time

def test_sha256():
    total_time = 0
    random_data = os.urandom(128)
    for _ in range(TEST_TIMES):
        total_time += calculate_sha256_time(random_data)
    return total_time

# ECC related functions
def calculate_ecc_point_multiplication_time():
    private_key = random.randint(1, SECP256k1.order - 1)
    generator_point = SECP256k1.generator
    start_time = time.time()
    result_point = private_key * generator_point
    end_time = time.time()
    return end_time - start_time

def test_ecc():
    total_time = 0
    for _ in range(TEST_TIMES):
        execution_time = calculate_ecc_point_multiplication_time()
        total_time += execution_time
    return total_time


# Scalar multiplication related functions
def calculate_scalar_multiplication_time():
    private_key = random.randint(1, SECP256k1.order - 1)
    generator_point = SECP256k1.generator
    start_time = time.time()
    result_point = private_key * generator_point
    end_time = time.time()
    return end_time - start_time

def test_scalar_multiplication():
    total_time = 0
    for _ in range(TEST_TIMES):
        execution_time = calculate_scalar_multiplication_time()
        total_time += execution_time
    return total_time

# ECC point-addition timing ##############################################
def calculate_ecc_point_add_time() -> float:
    """Time a single SECP256k1 point addition (G + G)."""
    start = time.perf_counter()
    _ = SECP256k1.generator + SECP256k1.generator   # point addition
    end = time.perf_counter()
    return end - start

def test_ecc_point_addition() -> float:
    """Total time for TEST_TIMES point additions."""
    return sum(calculate_ecc_point_add_time() for _ in range(TEST_TIMES))

def test_reproduce_key_time():
    # Create a Fuzzy Extractor instance, with a 16-byte input and a Hamming distance threshold of 8
    extractor = FuzzyExtractor(32, 3)

    # Original input value (e.g., biometric data)
    original_value = b'AABBCCDDEEFFGGHHAABBCCDDEEFFGGHH'
    close_value = b'AABBCCDDEEFFGGHHAABBCCDDEEFFGGHI'  # A value close to the original one

    # Generate a key and helper data
    key, helper = extractor.generate(original_value)

    # Test the time to reproduce the key 10,000 times
    total_time = 0

    for _ in range(TEST_TIMES):
        start_time = time.time()
        reproduced_key = extractor.reproduce(close_value, helper)
        end_time = time.time()
        total_time += (end_time - start_time)

    return total_time

def calculate_aes_ctr_encrypt_time(data: bytes, key: bytes) -> float:
    """Time AES-CTR encryption only."""
    nonce = os.urandom(8)                     # 64-bit nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    start = time.time()
    ct = cipher.encrypt(data)                 # encryption only
    end = time.time()
    return end - start, nonce, ct             # return nonce/ct so decryption can use them

def calculate_aes_ctr_decrypt_time(ct: bytes, key: bytes, nonce: bytes) -> float:
    """Time AES-CTR decryption only."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    start = time.time()
    pt = cipher.decrypt(ct)                   # decryption only
    end = time.time()
    return end - start

def test_aes_ctr_separate() -> tuple[float, float]:
    """Return (total encryption time, total decryption time)."""
    key = os.urandom(16)                      # AES-128 key
    data = os.urandom(128)                    # 128 B random plaintext
    enc_total = 0.0
    dec_total = 0.0

    for _ in range(TEST_TIMES):
        enc_time, nonce, ct = calculate_aes_ctr_encrypt_time(data, key)
        dec_time = calculate_aes_ctr_decrypt_time(ct, key, nonce)
        enc_total += enc_time
        dec_total += dec_time

    return enc_total, dec_total

if __name__ == "__main__":

    total_reproduce_key_time = test_reproduce_key_time()
    print(f"Fuzzy Extractor key reproduction total execution time: {total_reproduce_key_time:.6f} seconds")

    # Test SHA-1 for 10000 times
    total_sha256_time = test_sha256()
    print(f"SHA-256 total execution time: {total_sha256_time:.6f} seconds")


    # Test point multiplication for 10000 times
    total_ecc_point_mul_time = test_ecc()
    print(f"ECC Point multiplication total execution time: {total_ecc_point_mul_time:.6f} seconds")

    print(f"ECC Point addition total: {test_ecc_point_addition():.6f} s")

    enc_time, dec_time = test_aes_ctr_separate()
    print(f"AES-CTR encryption total: {enc_time:.6f} s")
    print(f"AES-CTR decryption total: {dec_time:.6f} s")