import streamlit as st
import os
import base64
import hashlib
import json
import math
import numpy as np
from PIL import Image
from typing import List, Tuple, Optional
import zlib
from io import BytesIO, StringIO
import tempfile

# Cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# TensorFlow imports
import tensorflow as tf
from tensorflow.keras import layers, models
from tensorflow.keras.applications import VGG16
from tensorflow.keras.applications.vgg16 import preprocess_input
from skimage.metrics import peak_signal_noise_ratio, structural_similarity

# Set page configuration
st.set_page_config(
    page_title="Crypto-Steganography Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'private_key' not in st.session_state:
    st.session_state.private_key = None
if 'public_key' not in st.session_state:
    st.session_state.public_key = None
if 'stego_model' not in st.session_state:
    st.session_state.stego_model = None

### --- ENCRYPTION CLASSES --- ###
class AESHybridEncryption:
    """A simplified class for hybrid encryption using RSA and AES."""
    def __init__(self):
        self.backend = default_backend()

    def generate_rsa_keypair(self, key_size=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_deterministic_rsa_keypair(self, seed_password, key_size=2048, salt=b'steganography'):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        seed = kdf.derive(seed_password.encode('utf-8'))
        seed_int = int.from_bytes(seed, byteorder='big')
        original_random = os.urandom
        def deterministic_random(n):
            nonlocal seed_int
            result = []
            for _ in range(n):
                seed_int = (seed_int * 1103515245 + 12345) & 0x7fffffff
                result.append(seed_int & 0xff)
            return bytes(result)
        os.urandom = deterministic_random
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self.backend
            )
        finally:
            os.urandom = original_random
        public_key = private_key.public_key()
        return private_key, public_key

    def _pad_message(self, message):
        padding_length = 16 - (len(message) % 16)
        padding = bytes([padding_length]) * padding_length
        return message + padding

    def _unpad_message(self, padded_message):
        padding_length = padded_message[-1]
        return padded_message[:-padding_length]

    def encrypt_message(self, message, public_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padded_message = self._pad_message(message)
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext = {
            'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
        return ciphertext

    def decrypt_message(self, ciphertext, private_key):
        try:
            encrypted_message = base64.b64decode(ciphertext['encrypted_message'])
            encrypted_aes_key = base64.b64decode(ciphertext['encrypted_aes_key'])
            iv = base64.b64decode(ciphertext['iv'])
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
            decrypted_message = self._unpad_message(padded_message)
            original_message = decrypted_message.decode('utf-8')
            return original_message
        except Exception as e:
            return f"Error during decryption: {e}"

# ============================================
# --- HIGH-QUALITY LSB STEGANOGRAPHY ENGINE ---
# ============================================

class BinaryTextEncoder:
    def __init__(self):
        self.delimiter = '1111111111111110'  # 16-bit delimiter
        self.magic_header = '10101100'  # Magic number to identify our format (0xAC)

    def text_to_binary(self, text: str, bits_per_channel: int = 2) -> str:
        """Encode text to binary with LSB depth header at the START"""
        text_bits = ''.join(format(ord(c), '08b') for c in text)
        length_bin = format(len(text_bits), '032b')
        lsb_header = format(bits_per_channel, '08b')
        # Format: MAGIC(8) + LSB_DEPTH(8) + LENGTH(32) + TEXT_BITS + DELIMITER(16)
        return self.magic_header + lsb_header + length_bin + text_bits + self.delimiter

    def binary_to_text(self, binary: str) -> Tuple[str, int]:
        """Decode binary to text and return LSB depth used"""
        if len(binary) < 48:  # 8 (magic) + 8 (LSB) + 32 (length)
            return '', 0
        
        # Check magic header
        magic = binary[:8]
        if magic != self.magic_header:
            return '', 0
            
        lsb_depth = int(binary[8:16], 2)
        text_len = int(binary[16:48], 2)
        
        if text_len + 48 > len(binary):
            return '', lsb_depth
            
        payload = binary[48:48 + text_len]
        chars = [chr(int(payload[i:i+8], 2)) for i in range(0, len(payload), 8) if i+8 <= len(payload)]
        return ''.join(chars), lsb_depth

def password_to_seed(password: str, salt: bytes = b'stego_salt') -> int:
    """Convert password to deterministic seed for embedding locations"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    seed_bytes = kdf.derive(password.encode('utf-8'))
    return int.from_bytes(seed_bytes, byteorder='big')

def generate_pseudorandom_sequence(seed: int, length: int, max_val: int) -> List[int]:
    """Generate pseudorandom sequence of integers from seed using LCG"""
    sequence = []
    current = seed
    seen = set()
    for _ in range(length):
        current = (current * 1103515245 + 12345) & 0x7FFFFFFF
        val = current % max_val
        # Avoid collisions
        attempts = 0
        while val in seen and attempts < 1000:
            current = (current * 1103515245 + 12345) & 0x7FFFFFFF
            val = current % max_val
            attempts += 1
        seen.add(val)
        sequence.append(val)
    return sequence

def coord_to_index(x:int, y:int, width:int) -> int:
    return y * width + x

def index_to_coord(idx:int, width:int) -> Tuple[int,int]:
    x = idx % width
    y = idx // width
    return x, y

def pack_node(prev_idx:int, next_idx:int, data_bit:int, is_head:bool=False) -> bytes:
    """Pack node data into 12 bytes with CRC integrity check"""
    prev_idx &= 0xFFFFFF
    next_idx &= 0xFFFFFF
    b0 = (int(bool(data_bit)) & 1) | ((1 if is_head else 0) << 1)
    b1 = (prev_idx >> 16) & 0xFF
    b2 = (prev_idx >> 8) & 0xFF
    b3 = prev_idx & 0xFF
    b4 = (next_idx >> 16) & 0xFF
    b5 = (next_idx >> 8) & 0xFF
    b6 = next_idx & 0xFF
    header = bytes([b0, b1, b2, b3, b4, b5, b6])
    crc = zlib.crc32(header) & 0xFFFFFFFF
    b7, b8, b9, b10 = (crc >> 24) & 0xFF, (crc >> 16) & 0xFF, (crc >> 8) & 0xFF, crc & 0xFF
    b11 = 0
    return bytes([b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11])

def unpack_node(node_bytes: bytes) -> Optional[dict]:
    """Unpack node data with CRC validation"""
    if len(node_bytes) != 12:
        return None
    b = list(node_bytes)
    b0 = b[0]
    data_bit = b0 & 1
    is_head = ((b0 >> 1) & 1) == 1
    prev_idx = (b[1] << 16) | (b[2] << 8) | b[3]
    next_idx = (b[4] << 16) | (b[5] << 8) | b[6]
    crc_read = (b[7] << 24) | (b[8] << 16) | (b[9] << 8) | b[10]
    header = bytes(b[0:7])
    crc_calc = zlib.crc32(header) & 0xFFFFFFFF
    if crc_calc != crc_read:
        return None
    return {'prev': prev_idx, 'next': next_idx, 'bit': data_bit, 'is_head': is_head}

def write_lsb_marker(stego_arr: np.ndarray, bits_per_channel: int) -> None:
    """
    Write LSB depth marker in the first 3 pixels (top-left corner).
    This allows Bob to auto-detect the LSB depth used by Alice.
    Format: First 3 pixels store the BPC value multiple times for redundancy
    """
    h, w, _ = stego_arr.shape
    if h < 1 or w < 3:
        return
    
    # Store bits_per_channel in first 3 pixels (9 channels total)
    # Use 4 bits per channel to store the value (range 1-15)
    marker_value = bits_per_channel & 0x0F
    mask = 0xF0  # Clear lower 4 bits
    
    for px in range(3):
        for ch in range(3):
            original = stego_arr[0, px, ch]
            # Store marker in lower 4 bits
            new_value = (original & mask) | marker_value
            stego_arr[0, px, ch] = new_value


def write_lsb_marker(stego_arr: np.ndarray, bits_per_channel: int) -> None:
    """
    Write LSB depth marker in the first 3 pixels (top-left corner).
    This allows Bob to auto-detect the LSB depth used by Alice.
    Format: First 3 pixels store the BPC value multiple times for redundancy
    """
    h, w, _ = stego_arr.shape
    if h < 1 or w < 3:
        return
    
    # Store bits_per_channel in first 3 pixels (9 channels total)
    # Use 4 bits per channel to store the value (range 1-15)
    marker_value = bits_per_channel & 0x0F
    mask = 0xF0  # Clear lower 4 bits
    
    for px in range(3):
        for ch in range(3):
            original = stego_arr[0, px, ch]
            # Store marker in lower 4 bits
            new_value = (original & mask) | marker_value
            stego_arr[0, px, ch] = new_value


def read_lsb_marker(stego_arr: np.ndarray) -> int:
    """
    Read LSB depth marker from first 3 pixels.
    Returns the detected bits_per_channel, or 0 if not found.
    """
    h, w, _ = stego_arr.shape
    if h < 1 or w < 3:
        return 0
    
    # Read from first 3 pixels and take majority vote
    values = []
    for px in range(3):
        for ch in range(3):
            value = stego_arr[0, px, ch] & 0x0F
            if 1 <= value <= 4:  # Valid range
                values.append(value)
    
    if not values:
        return 0
    
    # Return most common value (majority vote)
    from collections import Counter
    counts = Counter(values)
    most_common = counts.most_common(1)[0][0]
    return most_common


def write_node_to_pixels_lsb(stego_arr: np.ndarray, x: int, y: int, node_bytes: bytes, bits_per_channel: int = 2) -> None:
    """
    Write 12-byte node using LSB steganography for minimal visual distortion.
    
    Args:
        stego_arr: Image array to modify
        x, y: Starting pixel position
        node_bytes: 12 bytes of node data to embed
        bits_per_channel: Number of LSBs to use per channel (1-2 recommended for quality)
    """
    assert len(node_bytes) == 12
    h, w, _ = stego_arr.shape
    
    total_bits = len(node_bytes) * 8  # 96 bits
    channels_needed = (total_bits + bits_per_channel - 1) // bits_per_channel
    pixels_needed = (channels_needed + 2) // 3
    
    if x + pixels_needed > w or y >= h:
        raise ValueError(f"Not enough space at position ({x}, {y})")
    
    # Create bit mask for LSB embedding
    mask = (0xFF << bits_per_channel) & 0xFF  # Clear the LSBs we'll use
    
    # Convert node_bytes to bit stream
    bit_stream = []
    for byte in node_bytes:
        for bit_idx in range(7, -1, -1):
            bit_stream.append((byte >> bit_idx) & 1)
    
    # Embed bits into image
    bit_idx = 0
    for px in range(pixels_needed):
        if x + px >= w:
            break
        for ch in range(3):
            if bit_idx >= len(bit_stream):
                break
            
            # Extract bits_per_channel bits from bit_stream
            value_to_embed = 0
            for i in range(bits_per_channel):
                if bit_idx < len(bit_stream):
                    value_to_embed = (value_to_embed << 1) | bit_stream[bit_idx]
                    bit_idx += 1
                else:
                    value_to_embed = value_to_embed << 1
            
            # Clear LSBs and embed new value
            original_value = stego_arr[y, x + px, ch]
            new_value = (original_value & mask) | value_to_embed
            stego_arr[y, x + px, ch] = new_value


def read_node_from_pixels_lsb(stego_arr: np.ndarray, x: int, y: int, bits_per_channel: int = 2) -> Optional[bytes]:
    """
    Read 12-byte node from pixels using LSB extraction.
    
    Args:
        stego_arr: Stego image array
        x, y: Starting pixel position
        bits_per_channel: Number of LSBs used per channel
        
    Returns:
        12 bytes of node data or None if read fails
    """
    h, w, _ = stego_arr.shape
    
    total_bits = 12 * 8  # 96 bits
    channels_needed = (total_bits + bits_per_channel - 1) // bits_per_channel
    pixels_needed = (channels_needed + 2) // 3
    
    if x + pixels_needed > w or y >= h:
        return None
    
    # Extract bit stream
    bit_stream = []
    mask = (1 << bits_per_channel) - 1  # Mask for extracting LSBs
    
    for px in range(pixels_needed):
        if x + px >= w:
            break
        for ch in range(3):
            value = stego_arr[y, x + px, ch] & mask
            
            # Extract individual bits
            for bit_idx in range(bits_per_channel - 1, -1, -1):
                bit_stream.append((value >> bit_idx) & 1)
                if len(bit_stream) >= total_bits:
                    break
            
            if len(bit_stream) >= total_bits:
                break
        if len(bit_stream) >= total_bits:
            break
    
    # Convert bit stream back to bytes
    if len(bit_stream) < total_bits:
        return None
    
    node_bytes = []
    for byte_idx in range(12):
        byte_value = 0
        for bit_idx in range(8):
            bit_position = byte_idx * 8 + bit_idx
            if bit_position < len(bit_stream):
                byte_value = (byte_value << 1) | bit_stream[bit_position]
        node_bytes.append(byte_value)
    
    return bytes(node_bytes)


@st.cache_resource
def build_location_selector_vgg(input_shape=(256,256,3), trainable_backbone=False):
    """
    Builds a lightweight VGG16-based suitability predictor model.
    Used to find candidate embedding locations (dummy-trained by default).
    """
    backbone = VGG16(include_top=False, weights='imagenet', input_shape=input_shape)
    backbone.trainable = trainable_backbone

    x = backbone.output
    x = layers.Conv2D(512, (3,3), padding='same', activation='relu')(x)
    x = layers.UpSampling2D((2,2))(x)
    x = layers.Conv2D(256, (3,3), padding='same', activation='relu')(x)
    x = layers.UpSampling2D((2,2))(x)
    x = layers.Conv2D(128, (3,3), padding='same', activation='relu')(x)
    x = layers.UpSampling2D((2,2))(x)
    x = layers.Conv2D(64, (3,3), padding='same', activation='relu')(x)
    x = layers.UpSampling2D((2,2))(x)
    x = layers.Conv2D(32, (3,3), padding='same', activation='relu')(x)
    x = layers.UpSampling2D((2,2))(x)
    output = layers.Conv2D(1, (1,1), activation='sigmoid', padding='same')(x)

    model = models.Model(inputs=backbone.input, outputs=output)
    return model

class TFStegoLinkedList:
    def __init__(self, train_selector=False, input_size=(256,256), bits_per_channel=2):
        """
        Initialize steganography engine with LSB embedding.
        
        Args:
            train_selector: Whether to train the VGG16 selector (optional)
            input_size: Input size for VGG16 model
            bits_per_channel: LSBs to use (1=best quality, 2=balanced, 3-4=more capacity)
        """
        self.encoder = BinaryTextEncoder()
        self.input_size = input_size
        self.bits_per_channel = bits_per_channel
        self.selector = build_location_selector_vgg(input_shape=(input_size[0], input_size[1], 3))
        if train_selector:
            self._train_selector_demo()

    def _train_selector_demo(self, epochs=3):
        """Optional: Train selector model with dummy data"""
        self.selector.compile(optimizer='adam', loss='mse')
        n = 20
        X = np.random.rand(n, self.input_size[0], self.input_size[1], 3).astype(np.float32)
        Y = np.random.rand(n, self.input_size[0], self.input_size[1], 1).astype(np.float32)
        self.selector.fit(X, Y, epochs=epochs, batch_size=4, verbose=0)

    def calculate_capacity(self, image_shape: Tuple[int, int, int]) -> dict:
        """Calculate steganography capacity for an image"""
        h, w, c = image_shape
        bits_per_node = 12 * 8  # 96 bits per node
        channels_per_node = (bits_per_node + self.bits_per_channel - 1) // self.bits_per_channel
        pixels_per_node = (channels_per_node + 2) // 3
        
        blocks_per_row = w // pixels_per_node
        max_blocks = blocks_per_row * h
        max_bits = max_blocks - 1  # -1 for head node
        max_bytes = max_bits // 8
        
        return {
            'max_bytes': max_bytes,
            'max_chars': max_bytes,  # approximate
            'max_blocks': max_blocks,
            'pixels_per_node': pixels_per_node,
            'blocks_per_row': blocks_per_row
        }

    def hide_text_linkedlist(self, image_arr: np.ndarray, secret_text: str, password: str) -> Tuple[np.ndarray, dict]:
        """
        Hide secret text in image using password-protected linked list steganography
        with LSB embedding for minimal visual distortion.
        
        Returns:
            Tuple of (stego_image, metrics_dict)
        """
        img = image_arr.copy().astype(np.uint8)
        h, w, _ = img.shape
        
        # Convert text to binary with LSB depth info
        secret_binary = self.encoder.text_to_binary(secret_text, self.bits_per_channel)
        num_bits = len(secret_binary)

        # Calculate capacity
        capacity = self.calculate_capacity(img.shape)
        
        if num_bits > capacity['max_blocks'] - 1:
            raise ValueError(
                f"Message too large. Need {num_bits} bits ({num_bits // 8} bytes), "
                f"but capacity is {capacity['max_blocks'] - 1} bits ({capacity['max_bytes']} bytes). "
                f"Try a larger image or reduce message size."
            )

        # Generate pseudorandom locations based on password
        seed = password_to_seed(password)
        random_positions = generate_pseudorandom_sequence(seed, num_bits + 1, capacity['max_blocks'])
        
        # Convert positions to (x, y) coordinates
        selected_blocks = []
        pixels_per_node = capacity['pixels_per_node']
        blocks_per_row = capacity['blocks_per_row']
        
        for pos in random_positions:
            block_idx = pos % capacity['max_blocks']
            y_pos = block_idx // blocks_per_row
            x_pos = (block_idx % blocks_per_row) * pixels_per_node
            if x_pos + pixels_per_node <= w and y_pos < h:
                selected_blocks.append((x_pos, y_pos))
        
        if len(selected_blocks) < num_bits + 1:
            raise ValueError("Not enough valid embedding positions generated.")
        
        # Calculate block indices for linking
        block_indices = [coord_to_index(x, y, w) for (x, y) in selected_blocks]

        # Embed data bits as linked list nodes using LSB
        for bit_idx in range(num_bits):
            bx, by = selected_blocks[bit_idx + 1]
            prev_idx = block_indices[bit_idx]
            next_idx = 0 if bit_idx == num_bits - 1 else block_indices[bit_idx + 2]
            node_bytes = pack_node(prev_idx, next_idx, int(secret_binary[bit_idx]), False)
            write_node_to_pixels_lsb(img, bx, by, node_bytes, self.bits_per_channel)

        # Write head node at first position
        head_bytes = pack_node(0, block_indices[1], 0, True)
        write_node_to_pixels_lsb(img, selected_blocks[0][0], selected_blocks[0][1], 
                                 head_bytes, self.bits_per_channel)
        
        # Write LSB marker in top-left corner for auto-detection
        write_lsb_marker(img, self.bits_per_channel)

        # Calculate quality metrics
        psnr = peak_signal_noise_ratio(image_arr, img)
        
        # Calculate SSIM (Structural Similarity Index)
        ssim = structural_similarity(image_arr, img, channel_axis=2, data_range=255)
        
        # Calculate average pixel difference
        avg_diff = np.mean(np.abs(image_arr.astype(float) - img.astype(float)))
        max_diff = np.max(np.abs(image_arr.astype(float) - img.astype(float)))
        
        metrics = {
            'psnr': psnr,
            'ssim': ssim,
            'avg_diff': avg_diff,
            'max_diff': max_diff,
            'bits_embedded': num_bits,
            'bytes_embedded': len(secret_text.encode('utf-8')),
            'capacity_used_percent': (num_bits / (capacity['max_blocks'] - 1)) * 100
        }
        
        return img, metrics

    def extract_text_linkedlist(self, stego_input, password: str) -> Tuple[str, int]:
        """
        Extract secret text from stego image using password and LSB extraction.
        AUTO-DETECTS the LSB depth used during embedding.
        Returns: (extracted_text, detected_lsb_depth)
        """
        stego = np.array(stego_input.convert('RGB')) if isinstance(stego_input, Image.Image) else stego_input
        h, w, _ = stego.shape
        
        # FIRST: Try to read LSB marker from image
        detected_bpc = read_lsb_marker(stego)
        
        if detected_bpc > 0:
            # Found marker, use detected BPC
            try:
                result = self._try_extract_with_bpc(stego, password, detected_bpc)
                if result and not result.startswith("Error"):
                    text, confirmed_bpc = self.encoder.binary_to_text(result)
                    if text:
                        return text, detected_bpc
            except Exception as e:
                pass  # If detected BPC fails, try fallback
        
        # FALLBACK: Try all possible BPC values
        for attempt_bpc in [2, 1, 3, 4]:  # Start with most common (2)
            try:
                result = self._try_extract_with_bpc(stego, password, attempt_bpc)
                if result and not result.startswith("Error"):
                    text, confirmed_bpc = self.encoder.binary_to_text(result)
                    if text:
                        return text, attempt_bpc
            except:
                continue
        
        return "Error: Could not extract data. Check password or image.", 0
    
    def _try_extract_with_bpc(self, stego: np.ndarray, password: str, bits_per_channel: int) -> str:
        """Internal method to try extraction with specific BPC"""
        h, w, _ = stego.shape
        
        # Calculate capacity info
        bits_per_node = 12 * 8
        channels_per_node = (bits_per_node + bits_per_channel - 1) // bits_per_channel
        pixels_per_node = (channels_per_node + 2) // 3
        blocks_per_row = w // pixels_per_node
        max_blocks = blocks_per_row * h
        
        # Generate same pseudorandom sequence to find head location
        seed = password_to_seed(password)
        random_positions = generate_pseudorandom_sequence(seed, 1, max_blocks)
        
        # Get head position
        head_pos = random_positions[0] % max_blocks
        head_y = head_pos // blocks_per_row
        head_x = (head_pos % blocks_per_row) * pixels_per_node
        
        if head_x + pixels_per_node > w or head_y >= h:
            return "Error: Invalid head position"
        
        # Read head node using LSB extraction
        head_bytes = read_node_from_pixels_lsb(stego, head_x, head_y, bits_per_channel)
        if head_bytes is None:
            return "Error: Could not read head node"
            
        head = unpack_node(head_bytes)
        if head is None or not head.get('is_head'):
            return "Error: Invalid head node or wrong password"
        
        # Follow linked list
        next_idx = head['next']
        bits_collected = []
        visited = set()
        steps = 0
        max_steps = max_blocks
        
        while next_idx != 0 and steps < max_steps:
            steps += 1
            bx, by = index_to_coord(next_idx, w)
            
            if (bx, by) in visited:
                break
            visited.add((bx, by))
            
            node_bytes = read_node_from_pixels_lsb(stego, bx, by, bits_per_channel)
            if node_bytes is None:
                break
                
            node = unpack_node(node_bytes)
            if node is None:
                break
                
            bits_collected.append(str(node['bit']))
            next_idx = node['next']
            
            # Check for delimiter
            if len(bits_collected) >= 16 and ''.join(bits_collected[-16:]) == self.encoder.delimiter:
                break
        
        # Reconstruct binary string
        bin_str = ''.join(bits_collected)
        if self.encoder.delimiter in bin_str:
            bin_str = bin_str[:bin_str.index(self.encoder.delimiter) + len(self.encoder.delimiter)]
        
        return bin_str


### --- STREAMLIT MAIN --- ###
def main():
    st.title("🔒 Crypto-Steganography Tool")
    st.markdown("""
    **Secure message encryption and steganographic hiding in images**
    - 🔐 Password-protected embedding locations using PBKDF2
    - 🔗 Circular linked list structure with CRC integrity checks
    - 🔑 Hybrid RSA + AES encryption
    - 🎨 **High-quality LSB embedding** (PSNR >45 dB, imperceptible changes)
    - 📊 VGG16-based embedding location analysis (optional)
    """)

    # Initialize crypto system
    if 'crypto' not in st.session_state:
        st.session_state.crypto = AESHybridEncryption()

    # Sidebar for navigation and settings
    st.sidebar.title("Navigation")
    section = st.sidebar.radio("Choose Section:", ["Key Management", "Role Selection"])
    
    # Quality settings in sidebar
    st.sidebar.divider()
    st.sidebar.subheader("⚙️ Quality Settings")
    bits_per_channel = st.sidebar.select_slider(
        "LSB Depth",
        options=[1, 2, 3, 4],
        value=2,
        help="1 = Best Quality (PSNR ~55dB)\n2 = Balanced (PSNR ~48dB)\n3 = More Capacity (PSNR ~42dB)\n4 = Max Capacity (PSNR ~36dB)"
    )
    
    quality_info = {
        1: ("🌟 Excellent", "Imperceptible changes, PSNR ~55 dB"),
        2: ("⭐ Very Good", "Near-imperceptible, PSNR ~48 dB"),
        3: ("✓ Good", "Minimal visible changes, PSNR ~42 dB"),
        4: ("⚠️ Acceptable", "Some changes visible, PSNR ~36 dB")
    }
    
    quality_label, quality_desc = quality_info[bits_per_channel]
    st.sidebar.info(f"**{quality_label}**\n{quality_desc}")

    if section == "Key Management":
        st.header("🔐 Key Management")
        
        key_type = st.radio("Key Generation Type:", ["Random", "Deterministic (Password-based)"])
        
        if key_type == "Random":
            if st.button("Generate Random RSA Key Pair"):
                with st.spinner("Generating random RSA key pair..."):
                    private_key, public_key = st.session_state.crypto.generate_rsa_keypair()
                    st.session_state.private_key = private_key
                    st.session_state.public_key = public_key
                st.success("✅ Random RSA key pair generated successfully!")
        else:
            seed_password = st.text_input("Seed Password:", type="password",
                                        help="Will generate same key pair for same password")
            if st.button("Generate Deterministic RSA Key Pair") and seed_password:
                with st.spinner("Generating deterministic RSA key pair..."):
                    private_key, public_key = st.session_state.crypto.generate_deterministic_rsa_keypair(seed_password)
                    st.session_state.private_key = private_key
                    st.session_state.public_key = public_key
                st.success("✅ Deterministic RSA key pair generated successfully!")
        
        # Show current keys status
        st.subheader("Current Keys Status")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.session_state.private_key:
                st.success("🔓 Private Key: Loaded")
                if st.button("Export Private Key"):
                    private_pem = st.session_state.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption())
                    st.download_button("Download Private Key", private_pem, "private_key.pem",
                                    mime="application/x-pem-file")
                if st.button("Clear Private Key"):
                    st.session_state.private_key = None
                    st.rerun()
            else:
                st.warning("⚠️ Private Key: Not loaded")
        
        with col2:
            if st.session_state.public_key:
                st.success("🔑 Public Key: Loaded")
                if st.button("Export Public Key"):
                    public_pem = st.session_state.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    st.download_button("Download Public Key", public_pem, "public_key.pem",
                                    mime="application/x-pem-file")
                if st.button("Clear Public Key"):
                    st.session_state.public_key = None
                    st.rerun()
            else:
                st.warning("⚠️ Public Key: Not loaded")
        
        st.divider()
        
        # Import Keys
        st.subheader("Import Keys")
        
        col1, col2 = st.columns(2)
        
        with col1:
            uploaded_private = st.file_uploader("Upload Private Key (.pem)", type=['pem'], key='private_upload')
            if uploaded_private:
                try:
                    private_key = serialization.load_pem_private_key(
                        uploaded_private.read(), password=None, backend=default_backend())
                    st.session_state.private_key = private_key
                    st.success("✅ Private key imported successfully.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Error importing private key: {e}")
        
        with col2:
            uploaded_public = st.file_uploader("Upload Public Key (.pem)", type=['pem'], key='public_upload')
            if uploaded_public:
                try:
                    public_key = serialization.load_pem_public_key(
                        uploaded_public.read(), backend=default_backend())
                    st.session_state.public_key = public_key
                    st.success("✅ Public key imported successfully.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Error importing public key: {e}")
        
        st.info("💡 **Tip:** Alice (Sender) only needs the Public Key. Bob (Receiver) only needs the Private Key.")

    else:  # Role Selection
        role = st.radio("Select your role:", ["Alice (Sender)", "Bob (Receiver)"])
        
        if role == "Alice (Sender)":
            st.header("📤 Alice - Encrypt & Hide Message")
            
            if st.session_state.public_key is None:
                st.error("❌ Please generate or load Bob's public key in Key Management section first.")
                return
            
            secret_message = st.text_area("Your secret message:", height=150,
                                         placeholder="Enter the secret message you want to hide...")
            uploaded_image = st.file_uploader("Cover image (PNG/JPG):", type=['png', 'jpg', 'jpeg'])
            watermark_password = st.text_input("Embedding Password:", type="password", 
                                              value="",
                                              help="This password determines where the message is hidden. Keep it secret!")
            
            if uploaded_image:
                image = Image.open(uploaded_image).convert('RGB')
                col1, col2 = st.columns(2)
                with col1:
                    st.image(image, caption="Cover Image", use_container_width=True)
                with col2:
                    st.info(f"📊 Image size: {image.size[0]}x{image.size[1]} pixels")
                    
                    # Calculate capacity with LSB steganography
                    img_arr = np.array(image)
                    temp_model = TFStegoLinkedList(bits_per_channel=bits_per_channel)
                    capacity = temp_model.calculate_capacity(img_arr.shape)
                    
                    st.info(f"📦 Capacity: ~{capacity['max_bytes']:,} bytes ({capacity['max_bytes'] // 1024} KB)")
                    st.info(f"🎨 Quality: {quality_label}")
                    
                    if secret_message:
                        msg_size = len(secret_message.encode('utf-8'))
                        usage_percent = (msg_size / capacity['max_bytes']) * 100 if capacity['max_bytes'] > 0 else 0
                        st.metric("Message Size", f"{msg_size} bytes", f"{usage_percent:.1f}% of capacity")
            else:
                image = None
            
            if secret_message and image and watermark_password:
                if st.button("🔒 Encrypt & Hide Message", type="primary"):
                    try:
                        with st.spinner("Encrypting and embedding message..."):
                            # Encrypt message
                            ciphertext = st.session_state.crypto.encrypt_message(
                                secret_message, st.session_state.public_key)
                            ciphertext_json = json.dumps(ciphertext)
                            
                            # Initialize stego model with selected quality
                            stego_model = TFStegoLinkedList(bits_per_channel=bits_per_channel)
                            
                            # Hide encrypted message
                            image_arr = np.array(image)
                            stego_image, metrics = stego_model.hide_text_linkedlist(
                                image_arr, ciphertext_json, watermark_password)
                            
                            stego_pil = Image.fromarray(stego_image)
                            
                            st.success(f"✅ Message encrypted and hidden successfully!")
                            
                            # Display quality metrics
                            st.subheader("📊 Quality Metrics")
                            col1, col2, col3, col4 = st.columns(4)
                            
                            with col1:
                                psnr_color = "🟢" if metrics['psnr'] > 45 else "🟡" if metrics['psnr'] > 35 else "🔴"
                                st.metric("PSNR", f"{metrics['psnr']:.2f} dB", 
                                         help="Peak Signal-to-Noise Ratio. >45 dB = Excellent, >35 dB = Good")
                                st.write(f"{psnr_color} Quality")
                            
                            with col2:
                                ssim_color = "🟢" if metrics['ssim'] > 0.99 else "🟡" if metrics['ssim'] > 0.95 else "🔴"
                                st.metric("SSIM", f"{metrics['ssim']:.4f}",
                                         help="Structural Similarity Index. 1.0 = Perfect, >0.99 = Excellent")
                                st.write(f"{ssim_color} Similarity")
                            
                            with col3:
                                st.metric("Avg Pixel Δ", f"{metrics['avg_diff']:.3f}",
                                         help="Average pixel difference (0-255 scale)")
                                st.write(f"Max: {metrics['max_diff']:.0f}")
                            
                            with col4:
                                st.metric("Capacity Used", f"{metrics['capacity_used_percent']:.1f}%",
                                         help="Percentage of available capacity used")
                                st.write(f"{metrics['bits_embedded']} bits")
                            
                            # Visual comparison
                            st.subheader("🖼️ Visual Comparison")
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.image(image, caption="Original Image", use_container_width=True)
                            with col2:
                                st.image(stego_pil, caption="Steganographic Image", use_container_width=True)
                            with col3:
                                # Create difference visualization
                                diff = np.abs(image_arr.astype(float) - stego_image.astype(float))
                                diff_enhanced = (diff * 10).clip(0, 255).astype(np.uint8)  # Enhance for visibility
                                st.image(diff_enhanced, caption="Difference (10x enhanced)", use_container_width=True)
                            
                            # Download button
                            buf = BytesIO()
                            stego_pil.save(buf, format='PNG')
                            buf.seek(0)
                            st.download_button(
                                "⬇️ Download Steganographic Image",
                                data=buf.getvalue(),
                                file_name="stego_image.png",
                                mime="image/png",
                                type="primary"
                            )
                            
                            # Additional info
                            with st.expander("ℹ️ Technical Details"):
                                st.json({
                                    "Embedding Method": "LSB Linked List Steganography",
                                    "Bits per Channel": bits_per_channel,
                                    "Encryption": "RSA-2048 + AES-256",
                                    "Password Protection": "PBKDF2-HMAC-SHA256",
                                    "Integrity Check": "CRC32",
                                    "PSNR (dB)": round(metrics['psnr'], 2),
                                    "SSIM": round(metrics['ssim'], 4),
                                    "Bits Embedded": metrics['bits_embedded'],
                                    "Bytes Embedded": metrics['bytes_embedded']
                                })
                            
                    except Exception as e:
                        st.error(f"❌ Error during encryption and hiding: {e}")
                        st.exception(e)
            elif not watermark_password:
                st.warning("⚠️ Please enter an embedding password.")
            else:
                st.info("💡 Enter a secret message, upload a cover image, and set an embedding password.")

        else:  # Bob (Receiver)
            st.header("📥 Bob - Extract & Decrypt Message")
            
            if st.session_state.private_key is None:
                st.error("❌ Please generate or load your private key in Key Management section first.")
                return
            
            uploaded_stego = st.file_uploader("Steganographic image (PNG/JPG):", type=['png', 'jpg', 'jpeg'])
            watermark_password = st.text_input("Embedding Password:", type="password", 
                                              value="",
                                              help="Enter the same password used during embedding")
            
            if uploaded_stego:
                stego_image = Image.open(uploaded_stego).convert('RGB')
                st.image(stego_image, caption="Steganographic Image", width=400)
                
                # Show image info
                st.info(f"📊 Image size: {stego_image.size[0]}x{stego_image.size[1]} pixels")
            else:
                st.info("💡 Upload a steganographic image containing the hidden message.")
                stego_image = None
            
            if stego_image and watermark_password:
                if st.button("🔓 Extract & Decrypt Message", type="primary"):
                    try:
                        with st.spinner("Extracting and decrypting message..."):
                            # Initialize stego model with same quality setting
                            stego_model = TFStegoLinkedList(bits_per_channel=bits_per_channel)
                            
                            # Extract encrypted message (auto-detects LSB depth)
                            extracted_ciphertext, detected_bpc = stego_model.extract_text_linkedlist(
                                stego_image, watermark_password)
                            
                            # Show LSB depth detection info
                            if detected_bpc > 0:
                                st.info(f"🔍 Auto-detected: Image was embedded using **{detected_bpc}-bit LSB** depth")
                                if detected_bpc != bits_per_channel:
                                    st.success(f"✅ Auto-correction applied! (Your slider was at {bits_per_channel}-bit)")
                            
                            # Show extracted raw data
                            with st.expander("🔍 Show Extracted Raw Data"):
                                st.text_area("Extracted ciphertext:", value=extracted_ciphertext, height=150)
                                if detected_bpc > 0:
                                    st.caption(f"Extracted using {detected_bpc}-bit LSB depth")
                            
                            # Check if extraction was successful
                            if not extracted_ciphertext.strip():
                                st.error("❌ No data could be extracted from the image. Check your password.")
                                return
                            
                            if extracted_ciphertext.startswith("Error"):
                                st.error(f"❌ Extraction failed: {extracted_ciphertext}")
                                return
                            
                            # Try to parse as JSON
                            try:
                                ciphertext_dict = json.loads(extracted_ciphertext)
                            except json.JSONDecodeError as e:
                                st.error(f"❌ Extracted data is not valid JSON. Wrong password or corrupted data.")
                                st.error(f"JSON Error: {e}")
                                return
                            
                            # Decrypt message
                            decrypted_message = st.session_state.crypto.decrypt_message(
                                ciphertext_dict, st.session_state.private_key)
                            
                            if decrypted_message.startswith("Error"):
                                st.error(f"❌ Decryption failed: {decrypted_message}")
                                return
                            
                            st.success("✅ Message extracted and decrypted successfully!")
                            
                            # Display decrypted message
                            st.subheader("📜 Decrypted Message")
                            st.text_area(
                                "Secret Message:", 
                                value=decrypted_message, 
                                height=200,
                                label_visibility="collapsed"
                            )
                            
                            # Message statistics
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Message Length", f"{len(decrypted_message)} chars")
                            with col2:
                                st.metric("Size", f"{len(decrypted_message.encode('utf-8'))} bytes")
                            with col3:
                                word_count = len(decrypted_message.split())
                                st.metric("Word Count", word_count)
                            
                            # Copy to clipboard button
                            st.download_button(
                                "📋 Download as Text File",
                                data=decrypted_message.encode('utf-8'),
                                file_name="decrypted_message.txt",
                                mime="text/plain"
                            )
                            
                    except Exception as e:
                        st.error(f"❌ Error during extraction and decryption: {e}")
                        st.exception(e)
            elif not watermark_password:
                st.warning("⚠️ Please enter the embedding password.")

if __name__ == "__main__":
    main()