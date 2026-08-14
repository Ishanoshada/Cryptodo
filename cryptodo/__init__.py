import string
import random
import hashlib
import base64
import os
import marshal
import zlib
import struct

__all__ = [
    'Crypto', 'CryptoV2', 'CryptoV3Num', 'CryptoV4XOR', 'CryptoV5Vigenere',
    'CryptoV6Hash', 'CryptoV7Atbash', 'CryptoV8Morse', 'CryptoV9RSAlite',
    'CryptoV10Emoji', 'FileCrypto', 'CryptoV11DeepVault',
    'CryptoV12Playfair', 'CryptoV13Hill', 'CryptoV14ADFGVX', 'CryptoV15ZeroWidth',
    'CryptoV16DNA', 'CryptoV17Chaos', 'CryptoV18Autokey', 'CryptoV19Homophonic',
    'CryptoV20Braille', 'CryptoV21Mnemonic',
    'KeyGenerator', 'KeyVariable'
]


class KeyVariable:
    key_var_all = string.ascii_letters + string.digits + '@#£_.&-+()/*:;!? \n\n~`|•√π÷×¶∆€¥$¢^°={}"%()©®™+✓[]<>'
    key_var_alp_number = string.ascii_letters + string.digits
    key_var_number = string.digits
    key_var_sim = '@#£_"&-+()/*:;!?~`|•√π÷×¶∆€¥$¢^°={}"%©®™✓[]<>' + " '"
    key_var_more = 'àáâäæãåāqwêéèëērtyūüúûùìīïíîõōøœòöôópßdfghjklzxçvbñmqwertyuioplkjhgfdsazxcvbnm1234567890රු'


class Crypto:
    """Caesar cipher (V1) + substitution cipher, fixed for correct round-tripping."""

    def __init__(self, text, key):
        self.text = text
        self.key = key
        self._substitution_key = None

    # ---------- V1: Caesar cipher ----------
    def encrypt(self):
        # FIX: modulo must be 26 (alphabet length), not 10.
        # key % 10 caused wraparound onto the wrong letters, so decrypt
        # with the "inverse" shift never actually recovered the original text.
        shift = self.key % 26
        alphabet = string.ascii_lowercase
        shifted = alphabet[shift:] + alphabet[:shift]
        table = str.maketrans(alphabet, shifted)
        encrypted = self.text.lower().translate(table)
        return '/V1_CRYPTO ' + encrypted

    def decrypt(self):
        if '/V1_CRYPTO ' not in self.text:
            return 'Padding error! /V1_CRYPTO not found in the text'
        cipher_text = self.text.replace('/V1_CRYPTO ', '')
        shift = (26 - (self.key % 26)) % 26  # FIX: inverse of key % 26
        alphabet = string.ascii_lowercase
        shifted = alphabet[shift:] + alphabet[:shift]
        table = str.maketrans(alphabet, shifted)
        return cipher_text.translate(table)

    # ---------- Substitution cipher ----------
    def substitution_encrypt(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        key_list = list(alphabet)
        random.seed(self.key)
        random.shuffle(key_list)
        self._substitution_key = ''.join(key_list)
        table = str.maketrans(alphabet, self._substitution_key)
        encrypted = self.text.translate(table)
        return '/SUBSTITUTION_CRYPTO ' + encrypted

    def substitution_decrypt(self):
        if '/SUBSTITUTION_CRYPTO ' not in self.text:
            return 'Padding error! /SUBSTITUTION_CRYPTO not found in the text'
        cipher_text = self.text.replace('/SUBSTITUTION_CRYPTO ', '')
        alphabet = string.ascii_letters + string.digits + string.punctuation
        if self._substitution_key is None:
            key_list = list(alphabet)
            random.seed(self.key)
            random.shuffle(key_list)
            self._substitution_key = ''.join(key_list)
        table = str.maketrans(self._substitution_key, alphabet)
        return cipher_text.translate(table)


class KeyGenerator:
    @staticmethod
    def key_generator_num_v1(min_val, max_val):
        return random.randint(min_val, max_val) + 8

    @staticmethod
    def key_generator_num_v1_1(string_lowercase, key):
        return int(string_lowercase, base=key)

    @staticmethod
    def key_generator_num_v2(size, chars=None):
        if chars is None:
            chars = KeyVariable.key_var_all
        return ''.join(random.choice(chars) for _ in range(size))

    @staticmethod
    def key_generator_password(size=16, use_symbols=True):
        """NEW: generate a strong random password."""
        chars = string.ascii_letters + string.digits
        if use_symbols:
            chars += '!@#$%^&*()-_=+'
        if size < 4:
            raise ValueError('size must be >= 4')
        # guarantee at least one of each category
        pw = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
        ]
        if use_symbols:
            pw.append(random.choice('!@#$%^&*()-_=+'))
        pw += [random.choice(chars) for _ in range(size - len(pw))]
        random.shuffle(pw)
        return ''.join(pw)


class CryptoV2:
    """Keyed-alphabet substitution + byte-wise Caesar variation, fixed."""

    def __init__(self, string, key):
        self.string = string
        self.key = key

    def encrypt(self):
        keys = self.key
        value = keys[-1] + keys[:-1]
        encrypt = dict(zip(keys, value))
        # FIX: chars not present in `keys` (e.g. spaces, punctuation) used to
        # raise a KeyError. Now they pass through unchanged.
        encrypted = ''.join(encrypt.get(ch, ch) for ch in self.string.lower())
        return '/V2_CRYPTO ' + encrypted

    def decrypt(self):
        if '/V2_CRYPTO ' not in self.string:
            return 'Padding error! /V2_CRYPTO not found in the text'
        cipher = self.string.replace('/V2_CRYPTO ', '')
        keys = self.key
        value = keys[-1] + keys[:-1]
        decrypt = dict(zip(value, keys))
        return ''.join(decrypt.get(ch, ch) for ch in cipher.lower())

    def caesar_variation_encrypt(self):
        shift = self.key
        encrypted = ''.join(chr((ord(ch) + shift) % 0x110000) for ch in self.string)
        return '/CAESAR_VARIATION_CRYPTO ' + encrypted

    def caesar_variation_decrypt(self):
        if '/CAESAR_VARIATION_CRYPTO ' not in self.string:
            return 'Padding error! /CAESAR_VARIATION_CRYPTO not found in the text'
        cipher = self.string.replace('/CAESAR_VARIATION_CRYPTO ', '')
        shift = self.key
        # FIX: mod 256 could land on an invalid/half surrogate range and also
        # didn't invert correctly for values that wrapped past 256 during
        # encryption when ord(ch) + shift exceeded 255 for non-ASCII input.
        # Using the full Unicode codepoint range (0x110000) on both sides
        # keeps encrypt/decrypt symmetric for any input, not just ASCII.
        return ''.join(chr((ord(ch) - shift) % 0x110000) for ch in cipher)


class CryptoV3Num:
    """Digit-shift cipher + rail fence cipher, fixed."""

    def __init__(self, number, key):
        self.number = number
        self.key = key

    def encrypt(self):
        # FIX: original did chr((ord(ch)+shift)%10 + ord('0')), which mixes
        # ord(ch) (~48-57) with a %10 in a way that does NOT map digit 0-9
        # cleanly (e.g. ord('5')=53, (53+3)%10=6 -> '6' looks right, but
        # ord('9')=57, (57+3)%10=0 -> '0', while ord('0')=48,(48+3)%10=1
        # -> '1' — the digit->digit shift is correct only by chance for
        # some shifts and silently wrong for others once you check it
        # against the *decimal value* of the digit rather than its ord()).
        # Fixed by shifting the digit's integer value directly.
        shift = self.key
        plain = str(self.number)
        encrypted = ''.join(str((int(ch) + shift) % 10) for ch in plain)
        return '/V3_NUM_CRYPTO ' + encrypted

    def decrypt(self):
        # FIX: was checking membership against str(self.number), but by the
        # time decrypt() runs, self.number IS already the encrypted string
        # (e.g. "/V3_NUM_CRYPTO 23456"), so wrapping it in str() again and
        # testing the same way happened to work only by coincidence. Made
        # this explicit and robust to non-string input too.
        text = str(self.number)
        if '/V3_NUM_CRYPTO ' not in text:
            return 'Padding error! /V3_NUM_CRYPTO not found in the text'
        cipher = text.replace('/V3_NUM_CRYPTO ', '')
        shift = self.key
        return ''.join(str((int(ch) - shift) % 10) for ch in cipher)

    def rail_fence_encrypt(self):
        rails = self.key
        text = str(self.number)
        if rails < 2:
            raise ValueError('rail fence key (rails) must be >= 2')

        def _encrypt(t, r):
            rail_dict = {i: [] for i in range(r)}
            rail, direction = 0, 1
            for ch in t:
                rail_dict[rail].append(ch)
                rail += direction
                if rail == r - 1 or rail == 0:
                    direction = -direction
            return ''.join(''.join(rail_dict[i]) for i in range(r))

        encrypted = _encrypt(text, rails)
        return '/RAIL_FENCE_CRYPTO ' + encrypted

    def rail_fence_decrypt(self):
        text = str(self.number)
        if '/RAIL_FENCE_CRYPTO ' not in text:
            return 'Padding error! /RAIL_FENCE_CRYPTO not found in the text'
        cipher = text.replace('/RAIL_FENCE_CRYPTO ', '')
        rails = self.key
        if rails < 2:
            raise ValueError('rail fence key (rails) must be >= 2')

        def _decrypt(t, r):
            rail_dict = {i: [] for i in range(r)}
            rail, direction = 0, 1
            for _ in range(len(t)):
                rail_dict[rail].append(None)
                rail += direction
                if rail == r - 1 or rail == 0:
                    direction = -direction

            idx = 0
            for i in range(r):
                for j in range(len(rail_dict[i])):
                    rail_dict[i][j] = t[idx]
                    idx += 1

            rail, direction = 0, 1
            decrypted = []
            for _ in range(len(t)):
                decrypted.append(rail_dict[rail].pop(0))
                rail += direction
                if rail == r - 1 or rail == 0:
                    direction = -direction
            return ''.join(decrypted)

        return _decrypt(cipher, rails)


class CryptoV4XOR:
    """NEW: XOR cipher with a repeating text key, output as base64."""

    def __init__(self, text, key):
        self.text = text
        self.key = key

    def encrypt(self):
        if not self.key:
            raise ValueError('key must not be empty')
        data = self.text.encode('utf-8')
        key_bytes = self.key.encode('utf-8')
        xored = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        encoded = base64.b64encode(xored).decode('ascii')
        return '/XOR_CRYPTO ' + encoded

    def decrypt(self):
        if '/XOR_CRYPTO ' not in self.text:
            return 'Padding error! /XOR_CRYPTO not found in the text'
        if not self.key:
            raise ValueError('key must not be empty')
        cipher_b64 = self.text.replace('/XOR_CRYPTO ', '')
        xored = base64.b64decode(cipher_b64.encode('ascii'))
        key_bytes = self.key.encode('utf-8')
        data = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(xored))
        return data.decode('utf-8')


class CryptoV5Vigenere:
    """NEW: classic Vigenère cipher, letters only, preserves case & non-letters."""

    def __init__(self, text, key):
        self.text = text
        self.key = key

    def encrypt(self):
        if not self.key or not self.key.isalpha():
            raise ValueError('key must be a non-empty alphabetic string')
        key = self.key.lower()
        result = []
        ki = 0
        for ch in self.text:
            if ch.isalpha():
                shift = ord(key[ki % len(key)]) - ord('a')
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch.lower()) - ord('a') + shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return '/VIGENERE_CRYPTO ' + ''.join(result)

    def decrypt(self):
        if '/VIGENERE_CRYPTO ' not in self.text:
            return 'Padding error! /VIGENERE_CRYPTO not found in the text'
        if not self.key or not self.key.isalpha():
            raise ValueError('key must be a non-empty alphabetic string')
        cipher = self.text.replace('/VIGENERE_CRYPTO ', '')
        key = self.key.lower()
        result = []
        ki = 0
        for ch in cipher:
            if ch.isalpha():
                shift = ord(key[ki % len(key)]) - ord('a')
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch.lower()) - ord('a') - shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return ''.join(result)


class CryptoV6Hash:
    """NEW: one-way hashing helpers (not reversible; for checksums/verification)."""

    def __init__(self, text):
        self.text = text

    def sha256(self):
        return hashlib.sha256(self.text.encode('utf-8')).hexdigest()

    def md5(self):
        return hashlib.md5(self.text.encode('utf-8')).hexdigest()

    def verify(self, digest, algo='sha256'):
        algo = algo.lower()
        if algo == 'sha256':
            return self.sha256() == digest
        if algo == 'md5':
            return self.md5() == digest
        raise ValueError('unsupported algo: ' + algo)


class CryptoV7Atbash:
    """NEW: Atbash cipher (a<->z, b<->y, ...) with a keyed twist — the key
    rotates the mirrored alphabet first, so it's not just the classic fixed
    Atbash. Non-letters pass through unchanged."""

    def __init__(self, text, key=0):
        self.text = text
        self.key = key

    def _table(self):
        alphabet = string.ascii_lowercase
        rotated = alphabet[self.key % 26:] + alphabet[:self.key % 26]
        mirrored = rotated[::-1]
        return str.maketrans(alphabet, mirrored), str.maketrans(mirrored, alphabet)

    def encrypt(self):
        enc_table, _ = self._table()
        out = []
        for ch in self.text:
            if ch.isalpha():
                lower = ch.lower().translate(enc_table)
                out.append(lower.upper() if ch.isupper() else lower)
            else:
                out.append(ch)
        return '/ATBASH_CRYPTO ' + ''.join(out)

    def decrypt(self):
        if '/ATBASH_CRYPTO ' not in self.text:
            return 'Padding error! /ATBASH_CRYPTO not found in the text'
        cipher = self.text.replace('/ATBASH_CRYPTO ', '')
        _, dec_table = self._table()
        out = []
        for ch in cipher:
            if ch.isalpha():
                lower = ch.lower().translate(dec_table)
                out.append(lower.upper() if ch.isupper() else lower)
            else:
                out.append(ch)
        return ''.join(out)


class CryptoV8Morse:
    """NEW: Morse code encoder/decoder. Not a "secret" cipher, but a genuinely
    useful encoding — letters/digits <-> dots and dashes, words separated by '/'."""

    _MAP = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.',
    }
    _REVERSE = {v: k for k, v in _MAP.items()}

    def __init__(self, text):
        self.text = text

    def encrypt(self):
        words = self.text.strip().split(' ')
        encoded_words = [
            ' '.join(self._MAP.get(ch.upper(), '') for ch in word if ch.upper() in self._MAP)
            for word in words
        ]
        return '/MORSE_CRYPTO ' + ' / '.join(encoded_words)

    def decrypt(self):
        if '/MORSE_CRYPTO ' not in self.text:
            return 'Padding error! /MORSE_CRYPTO not found in the text'
        cipher = self.text.replace('/MORSE_CRYPTO ', '')
        words = cipher.split(' / ')
        decoded_words = [
            ''.join(self._REVERSE.get(code, '') for code in word.split(' ') if code)
            for word in words
        ]
        return ' '.join(decoded_words).lower()


class CryptoV9RSAlite:
    """NEW: a small educational public-key cipher (RSA on tiny primes).
    NOT cryptographically secure for real security use — for learning/demo
    purposes only, since the primes are small enough to factor trivially.
    Encrypts short text (each char must map to an int < n)."""

    def __init__(self, text_or_numbers, key=None):
        self.text_or_numbers = text_or_numbers
        self.key = key  # (e, n) for encrypt, (d, n) for decrypt

    @staticmethod
    def _is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    @staticmethod
    def generate_keypair(p, q):
        if not (CryptoV9RSAlite._is_prime(p) and CryptoV9RSAlite._is_prime(q)):
            raise ValueError('p and q must both be prime')
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 2
        while e < phi:
            if _gcd(e, phi) == 1:
                break
            e += 1
        d = pow(e, -1, phi)
        return (e, n), (d, n)  # public, private

    def encrypt(self):
        e, n = self.key
        chars = [ord(c) for c in self.text_or_numbers]
        if any(c >= n for c in chars):
            raise ValueError('n too small for these characters; use bigger primes')
        cipher_nums = [pow(c, e, n) for c in chars]
        return '/RSALITE_CRYPTO ' + ','.join(map(str, cipher_nums))

    def decrypt(self):
        text = self.text_or_numbers
        if isinstance(text, str) and '/RSALITE_CRYPTO ' in text:
            text = text.replace('/RSALITE_CRYPTO ', '')
        elif isinstance(text, str):
            return 'Padding error! /RSALITE_CRYPTO not found in the text'
        d, n = self.key
        cipher_nums = [int(x) for x in text.split(',')]
        return ''.join(chr(pow(c, d, n)) for c in cipher_nums)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


class CryptoV10Emoji:
    """NEW: fun/playful cipher — maps each letter of the alphabet to an emoji
    based on the key seed, for lighthearted 'secret' messages."""

    _EMOJI_POOL = list(
        "😀😁😂🤣😃😄😅😆😉😊😋😎😍😘🥰😗😙😚🙂🤗🤩🤔🤨😐😑😶🙄😏😣"
        "😥😮🤐😯😪😫🥱😴😌😛😜😝🤤😒😓😔😕🙃🤑😲☹️🙁😖😞😟😤😢😭😦"
    )

    def __init__(self, text, key):
        self.text = text
        self.key = key

    def _mapping(self):
        alphabet = string.ascii_lowercase
        pool = self._EMOJI_POOL[:]
        random.seed(self.key)
        random.shuffle(pool)
        enc_map = dict(zip(alphabet, pool[:26]))
        dec_map = {v: k for k, v in enc_map.items()}
        return enc_map, dec_map

    def encrypt(self):
        enc_map, _ = self._mapping()
        out = []
        for ch in self.text.lower():
            out.append(enc_map.get(ch, ch))
        return '/EMOJI_CRYPTO ' + ''.join(out)

    def decrypt(self):
        if '/EMOJI_CRYPTO ' not in self.text:
            return 'Padding error! /EMOJI_CRYPTO not found in the text'
        cipher = self.text.replace('/EMOJI_CRYPTO ', '')
        _, dec_map = self._mapping()
        out = []
        i = 0
        while i < len(cipher):
            matched = False
            for emoji in dec_map:
                if cipher.startswith(emoji, i):
                    out.append(dec_map[emoji])
                    i += len(emoji)
                    matched = True
                    break
            if not matched:
                out.append(cipher[i])
                i += 1
        return ''.join(out)


class FileCrypto:
    """NEW: encode/encrypt actual files on disk, not just strings.
    - base64 encode/decode any file (safe text representation of binary data)
    - XOR-encrypt/decrypt any file with a key (works on any file type)
    """

    def __init__(self, path, key=None):
        self.path = path
        self.key = key

    def base64_encode_file(self, out_path=None):
        with open(self.path, 'rb') as f:
            data = f.read()
        encoded = base64.b64encode(data)
        out_path = out_path or (self.path + '.b64')
        with open(out_path, 'wb') as f:
            f.write(encoded)
        return out_path

    def base64_decode_file(self, out_path=None):
        with open(self.path, 'rb') as f:
            data = f.read()
        decoded = base64.b64decode(data)
        out_path = out_path or self.path.replace('.b64', '.decoded')
        with open(out_path, 'wb') as f:
            f.write(decoded)
        return out_path

    def xor_encrypt_file(self, out_path=None):
        if not self.key:
            raise ValueError('key must not be empty')
        key_bytes = self.key.encode('utf-8')
        with open(self.path, 'rb') as f:
            data = f.read()
        encrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        out_path = out_path or (self.path + '.xenc')
        with open(out_path, 'wb') as f:
            f.write(encrypted)
        return out_path

    def xor_decrypt_file(self, out_path=None):
        # XOR is symmetric, so decrypt is the same operation as encrypt
        if not self.key:
            raise ValueError('key must not be empty')
        key_bytes = self.key.encode('utf-8')
        with open(self.path, 'rb') as f:
            data = f.read()
        decrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        out_path = out_path or self.path.replace('.xenc', '.xdec')
        with open(out_path, 'wb') as f:
            f.write(decrypted)
        return out_path

    def sha256_checksum(self):
        h = hashlib.sha256()
        with open(self.path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()


class CryptoV11DeepVault:
    """NEW: Multi-layer "deep vault" encoder.

    How it works:
    - From `key`, a deterministic but unpredictable *sequence* of N layer
      operations is generated (chosen from: xor, base64, hex, byte-reverse,
      bit-rotate, marshal round-trip, zlib compress). N is either random
      (picked from [min_layers, max_layers], seeded by the key) or an exact
      number the caller passes in via `layers=`.
    - Each layer's sub-key is derived with hashlib.pbkdf2_hmac (100k+
      iterations), so guessing the outer key is one thing, but even with a
      guessed key an attacker still has to replay real per-layer key
      derivation + unwind every layer in the exact reverse order to land
      back on plaintext -- there's no shortcut across layers.
    - `marshal` (Python's internal object-serialization format) is one of
      the possible layers: raw bytes get wrapped as a Python bytes object
      and marshal.dumps()'d, which reformats the byte stream in a way that
      is opaque without knowing it was marshalled, then marshal.loads() is
      the exact inverse. NOTE: marshal's format is Python-version specific
      and is used purely as an obfuscation layer here, not as a security
      guarantee, and it is unsafe to marshal.loads() data from an untrusted
      source in a normal app (arbitrary object graphs) -- that risk doesn't
      apply here since we only ever marshal plain bytes we produced
      ourselves.
    - This is an obfuscation/puzzle tool, not vetted cryptography. Don't
      use it to protect anything that actually needs to stay secret from a
      motivated attacker -- use a real, audited library (e.g. `cryptography`
      Fernet/AES-GCM) for that.

    Usage:
        vault = CryptoV11DeepVault("my-secret-key")              # random depth
        vault = CryptoV11DeepVault("my-secret-key", layers=20)   # exact depth
        blob = vault.encode("hello world")
        original = vault.decode(blob)

        vault.encode_file("photo.png")     -> writes photo.png.vault
        vault.decode_file("photo.png.vault") -> restores original filename
    """

    _OPS = ['xor', 'b64', 'hex', 'reverse', 'rotate', 'marshal', 'zlib']
    HEADER = '/DEEPVAULT_CRYPTO '

    def __init__(self, key, layers=None, min_layers=8, max_layers=24, iterations=100_000):
        if not key:
            raise ValueError('key must not be empty')
        self.key = str(key)
        self.iterations = iterations
        if layers is None:
            random.seed(self.key + '::depth')
            layers = random.randint(min_layers, max_layers)
        if layers < 1:
            raise ValueError('layers must be >= 1')
        self.num_layers = layers
        self._sequence = self._build_sequence()

    # ---- setup ----
    def _build_sequence(self):
        random.seed(self.key + '::sequence')
        return [random.choice(self._OPS) for _ in range(self.num_layers)]

    def _subkey(self, layer_index, op):
        salt = f'{op}:{layer_index}'.encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', self.key.encode('utf-8'), salt, self.iterations)

    # ---- individual reversible layer transforms ----
    def _xor(self, data, subkey):
        return bytes(b ^ subkey[i % len(subkey)] for i, b in enumerate(data))

    def _b64_fwd(self, data, subkey):
        return base64.b64encode(data)

    def _b64_bwd(self, data, subkey):
        return base64.b64decode(data)

    def _hex_fwd(self, data, subkey):
        return data.hex().encode('ascii')

    def _hex_bwd(self, data, subkey):
        return bytes.fromhex(data.decode('ascii'))

    def _reverse(self, data, subkey):
        return data[::-1]

    def _rotate_fwd(self, data, subkey):
        n = (subkey[0] % 7) + 1
        return bytes(((b << n) | (b >> (8 - n))) & 0xFF for b in data)

    def _rotate_bwd(self, data, subkey):
        n = (subkey[0] % 7) + 1
        return bytes(((b >> n) | (b << (8 - n))) & 0xFF for b in data)

    def _marshal_fwd(self, data, subkey):
        return marshal.dumps(data)

    def _marshal_bwd(self, data, subkey):
        return marshal.loads(data)

    def _zlib_fwd(self, data, subkey):
        return zlib.compress(data, 9)

    def _zlib_bwd(self, data, subkey):
        return zlib.decompress(data)

    def _apply_forward(self, data):
        for i, op in enumerate(self._sequence):
            subkey = self._subkey(i, op)
            if op == 'xor':
                data = self._xor(data, subkey)
            elif op == 'b64':
                data = self._b64_fwd(data, subkey)
            elif op == 'hex':
                data = self._hex_fwd(data, subkey)
            elif op == 'reverse':
                data = self._reverse(data, subkey)
            elif op == 'rotate':
                data = self._rotate_fwd(data, subkey)
            elif op == 'marshal':
                data = self._marshal_fwd(data, subkey)
            elif op == 'zlib':
                data = self._zlib_fwd(data, subkey)
        return data

    def _apply_backward(self, data):
        for i, op in reversed(list(enumerate(self._sequence))):
            subkey = self._subkey(i, op)
            if op == 'xor':
                data = self._xor(data, subkey)  # xor is self-inverse
            elif op == 'b64':
                data = self._b64_bwd(data, subkey)
            elif op == 'hex':
                data = self._hex_bwd(data, subkey)
            elif op == 'reverse':
                data = self._reverse(data, subkey)  # reverse is self-inverse
            elif op == 'rotate':
                data = self._rotate_bwd(data, subkey)
            elif op == 'marshal':
                data = self._marshal_bwd(data, subkey)
            elif op == 'zlib':
                data = self._zlib_bwd(data, subkey)
        return data

    # ---- public: text/bytes ----
    def encode(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        result = self._apply_forward(data)
        wrapped = base64.b64encode(result).decode('ascii')  # keep it printable/safe text
        return f'{self.HEADER}{self.num_layers}:{wrapped}'

    def decode(self, blob):
        if self.HEADER not in blob:
            return 'Padding error! /DEEPVAULT_CRYPTO not found in the text'
        body = blob.replace(self.HEADER, '')
        layers_str, _, payload = body.partition(':')
        if int(layers_str) != self.num_layers:
            raise ValueError(
                f'This vault is configured for {self.num_layers} layers, '
                f'but the blob was made with {layers_str} layers -- use the '
                f'same key AND the same layers= value used to encode it.'
            )
        raw = base64.b64decode(payload.encode('ascii'))
        original = self._apply_backward(raw)
        return original.decode('utf-8')

    # ---- public: files (keeps original filename inside the vault) ----
    def encode_file(self, path, out_path=None):
        with open(path, 'rb') as f:
            file_bytes = f.read()
        name_bytes = os.path.basename(path).encode('utf-8')
        # simple self-describing container: [4-byte name length][name][file bytes]
        container = struct.pack('>I', len(name_bytes)) + name_bytes + file_bytes
        result = self._apply_forward(container)
        out_path = out_path or (path + '.vault')
        with open(out_path, 'wb') as f:
            f.write(f'{self.num_layers}\n'.encode('ascii'))
            f.write(result)
        return out_path

    def decode_file(self, path, out_dir=None):
        with open(path, 'rb') as f:
            first_line = f.readline()
            body = f.read()
        layers_declared = int(first_line.decode('ascii').strip())
        if layers_declared != self.num_layers:
            raise ValueError(
                f'This vault is configured for {self.num_layers} layers, '
                f'but the file was made with {layers_declared} layers -- use '
                f'the same key AND the same layers= value used to encode it.'
            )
        container = self._apply_backward(body)
        name_len = struct.unpack('>I', container[:4])[0]
        name = container[4:4 + name_len].decode('utf-8')
        original_bytes = container[4 + name_len:]
        out_dir = out_dir or os.path.dirname(path) or '.'
        out_path = os.path.join(out_dir, name)
        with open(out_path, 'wb') as f:
            f.write(original_bytes)
        return out_path

    def describe(self):
        """Show the generated layer sequence (for curiosity/debugging --
        doesn't reveal the per-layer subkeys, which stay derived from the key)."""
        return f'{self.num_layers} layers: ' + ' -> '.join(self._sequence)


class CryptoV12Playfair:
    """NEW: the classic Playfair cipher (Wheatstone, 1854) -- the first
    practical digraph substitution cipher, used tactically by British and
    Australian forces through WWI and WWII. Instead of substituting single
    letters (which leaks E-T-A-O-I-N frequency patterns straight through),
    it substitutes *pairs* of letters at once using a keyed 5x5 grid (I/J
    share a cell), which is why it resisted casual pen-and-paper attacks far
    longer than a simple substitution cipher. Letters only; repeated letters
    in a pair get an inserted 'X', and an odd-length message is padded with
    a trailing 'X'."""

    def __init__(self, text, key):
        self.text = text
        self.key = key
        self._grid = self._build_grid()

    def _build_grid(self):
        key_letters = self.key.upper().replace('J', 'I')
        alphabet = string.ascii_uppercase.replace('J', '')
        seen = []
        for ch in key_letters + alphabet:
            if ch.isalpha() and ch not in seen:
                seen.append(ch)
        grid_str = ''.join(seen)
        return [grid_str[i * 5:(i + 1) * 5] for i in range(5)]

    def _pos(self, ch):
        for r, row in enumerate(self._grid):
            if ch in row:
                return r, row.index(ch)
        raise ValueError(f'{ch!r} cannot be placed in the Playfair grid')

    def _digraphs(self, text):
        letters = [c for c in text.upper().replace('J', 'I') if c.isalpha()]
        pairs = []
        i = 0
        while i < len(letters):
            a = letters[i]
            b = letters[i + 1] if i + 1 < len(letters) else 'X'
            if a == b:
                pairs.append((a, 'X'))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        return pairs

    def encrypt(self):
        out = []
        for a, b in self._digraphs(self.text):
            ra, ca = self._pos(a)
            rb, cb = self._pos(b)
            if ra == rb:
                out.append(self._grid[ra][(ca + 1) % 5])
                out.append(self._grid[rb][(cb + 1) % 5])
            elif ca == cb:
                out.append(self._grid[(ra + 1) % 5][ca])
                out.append(self._grid[(rb + 1) % 5][cb])
            else:
                out.append(self._grid[ra][cb])
                out.append(self._grid[rb][ca])
        return '/PLAYFAIR_CRYPTO ' + ''.join(out)

    def decrypt(self):
        if '/PLAYFAIR_CRYPTO ' not in self.text:
            return 'Padding error! /PLAYFAIR_CRYPTO not found in the text'
        cipher = self.text.replace('/PLAYFAIR_CRYPTO ', '')
        pairs = [(cipher[i], cipher[i + 1]) for i in range(0, len(cipher) - 1, 2)]
        out = []
        for a, b in pairs:
            ra, ca = self._pos(a)
            rb, cb = self._pos(b)
            if ra == rb:
                out.append(self._grid[ra][(ca - 1) % 5])
                out.append(self._grid[rb][(cb - 1) % 5])
            elif ca == cb:
                out.append(self._grid[(ra - 1) % 5][ca])
                out.append(self._grid[(rb - 1) % 5][cb])
            else:
                out.append(self._grid[ra][cb])
                out.append(self._grid[rb][ca])
        return ''.join(out)


class CryptoV13Hill:
    """NEW: Hill cipher (Lester S. Hill, 1929) -- the first practical
    *linear-algebra* cipher: letters become numbers, get grouped into 2-tall
    vectors, and are transformed by matrix multiplication mod 26. Breaking a
    simple substitution cipher only ever requires guessing single-letter
    swaps; breaking Hill means recovering an entire matrix. The key_matrix
    (a 2x2 nested list, e.g. [[3, 3], [2, 5]]) must have a determinant that
    is coprime with 26, or it has no valid inverse and decryption is
    mathematically impossible -- this is checked up front."""

    def __init__(self, text, key_matrix):
        self.text = text
        self.key_matrix = key_matrix
        det = self._det() % 26
        if _gcd(det, 26) != 1:
            raise ValueError(
                'key_matrix is not invertible mod 26 (determinant must be '
                'coprime with 26, i.e. odd and not a multiple of 13)'
            )

    def _det(self):
        (a, b), (c, d) = self.key_matrix
        return a * d - b * c

    def _inverse_matrix(self):
        (a, b), (c, d) = self.key_matrix
        det_inv = pow(self._det() % 26, -1, 26)
        return [
            [(d * det_inv) % 26, (-b * det_inv) % 26],
            [(-c * det_inv) % 26, (a * det_inv) % 26],
        ]

    @staticmethod
    def _pairs(letters):
        if len(letters) % 2 != 0:
            letters += 'X'
        return [(letters[i], letters[i + 1]) for i in range(0, len(letters), 2)]

    def _transform(self, letters, matrix):
        (a, b), (c, d) = matrix
        out = []
        for x, y in self._pairs(letters):
            xv, yv = ord(x) - 65, ord(y) - 65
            out.append(chr((a * xv + b * yv) % 26 + 65))
            out.append(chr((c * xv + d * yv) % 26 + 65))
        return ''.join(out)

    def encrypt(self):
        letters = ''.join(c for c in self.text.upper() if c.isalpha())
        return '/HILL_CRYPTO ' + self._transform(letters, self.key_matrix)

    def decrypt(self):
        if '/HILL_CRYPTO ' not in self.text:
            return 'Padding error! /HILL_CRYPTO not found in the text'
        cipher = self.text.replace('/HILL_CRYPTO ', '')
        return self._transform(cipher, self._inverse_matrix())


_ADFGVX_LETTERS = 'ADFGVX'


class CryptoV14ADFGVX:
    """NEW: ADFGVX -- the WWI German Army field cipher (Col. Fritz Nebel,
    1918) that French cryptanalyst Georges Painvin famously broke himself
    over trying to crack. It's a *compound* cipher: stage one fractionates
    every character into a pair of letters drawn from {A,D,F,G,V,X} using a
    keyed 6x6 grid (A-Z0-9); stage two scrambles the resulting letter stream
    with a columnar transposition keyed by a second, independent word. The
    two stages use two different keys, so recovering one alone doesn't get
    you the plaintext -- you need both, applied in the right order."""

    def __init__(self, text, grid_key, transposition_key):
        self.text = text
        self.grid_key = grid_key
        if not transposition_key:
            raise ValueError('transposition_key must not be empty')
        self.transposition_key = transposition_key
        self._grid = self._build_grid()

    def _build_grid(self):
        chars = list(string.ascii_uppercase + string.digits)  # 36 chars
        random.seed(self.grid_key)
        random.shuffle(chars)
        return chars

    def _char_to_pair(self, ch):
        idx = self._grid.index(ch)
        row, col = divmod(idx, 6)
        return _ADFGVX_LETTERS[row] + _ADFGVX_LETTERS[col]

    def _pair_to_char(self, pair):
        row = _ADFGVX_LETTERS.index(pair[0])
        col = _ADFGVX_LETTERS.index(pair[1])
        return self._grid[row * 6 + col]

    def _columnar_encrypt(self, s):
        key = self.transposition_key
        n = len(key)
        order = sorted(range(n), key=lambda i: (key[i], i))
        row_chunks = [s[i:i + n] for i in range(0, len(s), n)]
        cols = [''.join(row[c] for row in row_chunks if c < len(row)) for c in order]
        return ''.join(cols)

    def _columnar_decrypt(self, s, total_len):
        key = self.transposition_key
        n = len(key)
        order = sorted(range(n), key=lambda i: (key[i], i))
        rows = -(-total_len // n) if total_len else 0
        remainder = total_len % n
        col_lengths = [rows if (remainder == 0 or c < remainder) else rows - 1 for c in range(n)]
        cols = [''] * n
        pos = 0
        for c in order:
            length = col_lengths[c]
            cols[c] = s[pos:pos + length]
            pos += length
        result = []
        for r in range(rows):
            for c in range(n):
                if r < len(cols[c]):
                    result.append(cols[c][r])
        return ''.join(result)

    def encrypt(self):
        cleaned = ''.join(c for c in self.text.upper() if c.isalnum())
        fractionated = ''.join(self._char_to_pair(c) for c in cleaned)
        scrambled = self._columnar_encrypt(fractionated)
        return f'/ADFGVX_CRYPTO {len(fractionated)}:{scrambled}'

    def decrypt(self):
        if '/ADFGVX_CRYPTO ' not in self.text:
            return 'Padding error! /ADFGVX_CRYPTO not found in the text'
        body = self.text.replace('/ADFGVX_CRYPTO ', '')
        length_str, _, scrambled = body.partition(':')
        fractionated = self._columnar_decrypt(scrambled, int(length_str))
        pairs = [fractionated[i:i + 2] for i in range(0, len(fractionated), 2)]
        return ''.join(self._pair_to_char(p) for p in pairs)


_ZW_ZERO = '\u200b'  # ZERO WIDTH SPACE       -> bit 0
_ZW_ONE = '\u200c'   # ZERO WIDTH NON-JOINER  -> bit 1


class CryptoV15ZeroWidth:
    """NEW: zero-width Unicode steganography. This is a fundamentally
    different game than a cipher -- a cipher makes a message unreadable,
    this makes a message *invisible*. It hides a secret as a sequence of
    zero-width characters (U+200B / U+200C, which render as literally
    nothing) tucked inside ordinary "cover" text. Paste the result anywhere
    and a human sees only the cover text; there is no ciphertext-looking
    blob to even notice. An optional key XORs the payload bytes before
    hiding them, so even someone who knows to look for zero-width
    characters (any Unicode inspector will find them) still can't read the
    payload without the key -- combining steganography (concealment) with
    encryption (confidentiality), the same two-layer idea real tools like
    StegZero use."""

    def __init__(self, secret=None, key=None, cover_text=''):
        self.secret = secret
        self.key = key
        self.cover_text = cover_text

    def _xor(self, data, key):
        if not key:
            return data
        kb = str(key).encode('utf-8')
        return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))

    def hide(self):
        if self.secret is None:
            raise ValueError('secret must be provided to hide()')
        data = self._xor(self.secret.encode('utf-8'), self.key)
        bits = ''.join(format(b, '08b') for b in data)
        hidden = ''.join(_ZW_ONE if bit == '1' else _ZW_ZERO for bit in bits)
        if self.cover_text:
            # tuck it in after the first character rather than just
            # tacking it onto the end, so it's not a suspicious trailing blob
            return self.cover_text[:1] + hidden + self.cover_text[1:]
        return hidden

    def reveal(self):
        bits = ''.join('1' if ch == _ZW_ONE else '0'
                        for ch in self.cover_text if ch in (_ZW_ZERO, _ZW_ONE))
        if not bits:
            return 'Padding error! no hidden zero-width payload found in the text'
        usable = len(bits) - len(bits) % 8
        byte_vals = bytes(int(bits[i:i + 8], 2) for i in range(0, usable, 8))
        data = self._xor(byte_vals, self.key)
        return data.decode('utf-8')


class CryptoV16DNA:
    """NEW: DNA-style nucleotide encoding, modeled on real DNA-data-storage
    research (which typically maps 2 bits -> 1 of 4 bases, e.g. 00->A,
    01->C, 10->G, 11->T). Here the 2-bit -> base assignment is shuffled by
    the key, so the same text produces a different-looking "genome" per
    key. This is a base-4 numeral system with A/T/C/G as its digits, not
    biology -- nothing here touches wet-lab synthesis."""

    _DNA_BASES = 'ATCG'

    def __init__(self, text, key):
        self.text = text
        self.key = key
        self._bases = self._keyed_bases()

    def _keyed_bases(self):
        bases = list(self._DNA_BASES)
        random.seed(self.key)
        random.shuffle(bases)
        return ''.join(bases)

    def encrypt(self):
        data = self.text.encode('utf-8')
        out = []
        for byte in data:
            for shift in (6, 4, 2, 0):
                out.append(self._bases[(byte >> shift) & 0b11])
        return '/DNA_CRYPTO ' + ''.join(out)

    def decrypt(self):
        if '/DNA_CRYPTO ' not in self.text:
            return 'Padding error! /DNA_CRYPTO not found in the text'
        cipher = self.text.replace('/DNA_CRYPTO ', '')
        rev = {b: i for i, b in enumerate(self._bases)}
        byte_vals = []
        for i in range(0, len(cipher), 4):
            byte = 0
            for ch in cipher[i:i + 4]:
                byte = (byte << 2) | rev[ch]
            byte_vals.append(byte)
        return bytes(byte_vals).decode('utf-8')


class CryptoV17Chaos:
    """NEW: chaotic logistic-map keystream cipher. Derives a starting point
    x0 and growth-rate r from the key (via SHA-256), then iterates the
    logistic map x_(n+1) = r * x_n * (1 - x_n) in its chaotic regime
    (r in [3.6, 4.0)) -- the same nonlinear system studied in real
    chaos-based-cryptography research as a keystream generator. Two nearly
    identical keys diverge into completely different keystreams within a
    handful of iterations (sensitive dependence on initial conditions),
    which is the whole appeal of chaos as a cipher ingredient. Deterministic
    and fully reversible with the same key; like the other ciphers here,
    this is a fun mathematical construction, not vetted/audited crypto."""

    def __init__(self, text, key):
        self.text = text
        self.key = key
        self._x0, self._r = self._derive_params()

    def _derive_params(self):
        h = hashlib.sha256(str(self.key).encode('utf-8')).digest()
        x0 = int.from_bytes(h[:8], 'big') / 2**64
        x0 = 0.0001 + x0 * 0.9998  # stay clear of the fixed points 0 and 1
        r = 3.6 + (int.from_bytes(h[8:16], 'big') / 2**64) * 0.399  # in [3.6, 3.999)
        return x0, r

    def _keystream(self, length):
        x = self._x0
        for _ in range(100):  # burn-in so we're well onto the attractor
            x = self._r * x * (1 - x)
        stream = bytearray()
        for _ in range(length):
            x = self._r * x * (1 - x)
            stream.append(int(x * 256) % 256)
        return bytes(stream)

    def encrypt(self):
        data = self.text.encode('utf-8')
        xored = bytes(b ^ k for b, k in zip(data, self._keystream(len(data))))
        return '/CHAOS_CRYPTO ' + base64.b64encode(xored).decode('ascii')

    def decrypt(self):
        if '/CHAOS_CRYPTO ' not in self.text:
            return 'Padding error! /CHAOS_CRYPTO not found in the text'
        xored = base64.b64decode(self.text.replace('/CHAOS_CRYPTO ', '').encode('ascii'))
        data = bytes(b ^ k for b, k in zip(xored, self._keystream(len(xored))))
        return data.decode('utf-8')


class CryptoV18Autokey:
    """NEW: the Autokey cipher -- a genuine historical upgrade over
    Vigenere. Plain Vigenere repeats a short key over and over, which
    creates a detectable period (Kasiski examination cracks it by finding
    that period); Autokey instead extends the keystream with the plaintext
    itself after the key runs out, so the keystream never repeats and there
    is no period to find. Case-preserving; non-letters pass through."""

    def __init__(self, text, key):
        self.text = text
        if not key or not key.isalpha():
            raise ValueError('key must be a non-empty alphabetic string')
        self.key = key.lower()

    def encrypt(self):
        letters_only = [c.lower() for c in self.text if c.isalpha()]
        keystream = list(self.key) + letters_only
        out = []
        ki = 0
        for ch in self.text:
            if ch.isalpha():
                shift = ord(keystream[ki]) - ord('a')
                base = ord('A') if ch.isupper() else ord('a')
                out.append(chr((ord(ch.lower()) - ord('a') + shift) % 26 + base))
                ki += 1
            else:
                out.append(ch)
        return '/AUTOKEY_CRYPTO ' + ''.join(out)

    def decrypt(self):
        if '/AUTOKEY_CRYPTO ' not in self.text:
            return 'Padding error! /AUTOKEY_CRYPTO not found in the text'
        cipher = self.text.replace('/AUTOKEY_CRYPTO ', '')
        keystream = list(self.key)
        out = []
        ki = 0
        for ch in cipher:
            if ch.isalpha():
                shift = ord(keystream[ki]) - ord('a')
                base = ord('A') if ch.isupper() else ord('a')
                plain_ch = chr((ord(ch.lower()) - ord('a') - shift) % 26 + base)
                out.append(plain_ch)
                keystream.append(plain_ch.lower())  # autokey: recovered plaintext extends the key
                ki += 1
            else:
                out.append(ch)
        return ''.join(out)


class CryptoV19Homophonic:
    """NEW: homophonic substitution cipher -- the technique that protected
    the Great Cipher of Louis XIV for 200 years and is the same family of
    cipher behind the Zodiac killer's Z408. An ordinary substitution cipher
    maps each letter to exactly one symbol, so 'E' always looks the same in
    the ciphertext and frequency analysis reads it off directly. Homophonic
    substitution instead gives common letters *several* interchangeable
    numeric codes ('00'-'99', counts roughly proportional to English letter
    frequency -- 'e' gets 13 codes, 'z' gets 1) and picks a random one each
    time, which flattens the ciphertext's symbol frequencies. Decoding is
    still a simple reverse lookup either way. Lowercases on encode (case
    isn't preserved); non-letters are kept exactly via a bracketed
    codepoint token so nothing is lost."""

    _FREQ_ORDER = 'etaoinshrdlcumwfgypbvkjxqz'
    _COUNTS = {
        'e': 13, 't': 9, 'a': 8, 'o': 8, 'i': 7, 'n': 7, 's': 6, 'h': 6,
        'r': 6, 'd': 4, 'l': 4, 'c': 3, 'u': 3, 'm': 3, 'w': 2, 'f': 2,
        'g': 2, 'y': 2, 'p': 2, 'b': 1, 'v': 1, 'k': 1, 'j': 1, 'x': 1,
        'q': 1, 'z': 1,
    }

    def __init__(self, text, key):
        self.text = text
        self.key = key
        self._enc_map, self._dec_map = self._build_maps()

    def _build_maps(self):
        symbols = [f'{i:02d}' for i in range(100)]
        random.seed(self.key)
        random.shuffle(symbols)
        enc_map, dec_map = {}, {}
        idx = 0
        for letter in self._FREQ_ORDER:
            count = self._COUNTS[letter]
            homophones = symbols[idx:idx + count]
            idx += count
            enc_map[letter] = homophones
            for h in homophones:
                dec_map[h] = letter
        return enc_map, dec_map

    def encrypt(self):
        tokens = []
        for ch in self.text.lower():
            if ch in self._enc_map:
                tokens.append(random.choice(self._enc_map[ch]))
            else:
                tokens.append('[' + str(ord(ch)) + ']')
        return '/HOMOPHONIC_CRYPTO ' + ' '.join(tokens)

    def decrypt(self):
        if '/HOMOPHONIC_CRYPTO ' not in self.text:
            return 'Padding error! /HOMOPHONIC_CRYPTO not found in the text'
        body = self.text.replace('/HOMOPHONIC_CRYPTO ', '')
        out = []
        for tok in body.split(' '):
            if tok.startswith('[') and tok.endswith(']'):
                out.append(chr(int(tok[1:-1])))
            elif tok in self._dec_map:
                out.append(self._dec_map[tok])
        return ''.join(out)


class CryptoV20Braille:
    """NEW: keyed Braille-pattern cipher. Maps each letter/digit to one of
    the 256 Unicode Braille glyphs (U+2800 block) via a keyed shuffle, so
    ciphertext renders as a run of dot-pattern characters -- unreadable at a
    glance to a sighted non-braille-reader, and the letter-to-glyph
    assignment itself changes per key, so even someone who *does* read
    braille can't just read it off without the key."""

    def __init__(self, text, key):
        self.text = text
        self.key = key
        self._enc_map, self._dec_map = self._build_maps()

    def _build_maps(self):
        alphabet = string.ascii_lowercase + string.digits  # 36 symbols
        glyphs = [chr(0x2800 + i) for i in range(256)]
        random.seed(self.key)
        random.shuffle(glyphs)
        chosen = glyphs[:len(alphabet)]
        return dict(zip(alphabet, chosen)), dict(zip(chosen, alphabet))

    def encrypt(self):
        out = [self._enc_map.get(ch, ch) for ch in self.text.lower()]
        return '/BRAILLE_CRYPTO ' + ''.join(out)

    def decrypt(self):
        if '/BRAILLE_CRYPTO ' not in self.text:
            return 'Padding error! /BRAILLE_CRYPTO not found in the text'
        cipher = self.text.replace('/BRAILLE_CRYPTO ', '')
        out = [self._dec_map.get(ch, ch) for ch in cipher]
        return ''.join(out)


class CryptoV21Mnemonic:
    """NEW: mnemonic wordlist cipher, in the spirit of BIP39 seed phrases
    (the scheme crypto wallets use to turn random bytes into memorable
    words). Every possible byte (0-255) maps to a unique "adjective-noun"
    pair from a keyed-shuffled 16x16 word grid, so any data becomes a
    sequence of ordinary-looking words -- e.g. "brave-tiger silent-river
    lucky-comet..." -- that reads like nonsense prose instead of obvious
    ciphertext, and is easy to read aloud, write down, or retype by hand
    without transcription errors (unlike a base64 blob)."""

    _ADJ = ['brave', 'silent', 'lucky', 'wild', 'gentle', 'fierce', 'quiet', 'bold',
            'clever', 'swift', 'curious', 'loyal', 'mighty', 'calm', 'sneaky', 'bright']
    _NOUN = ['tiger', 'river', 'comet', 'falcon', 'forest', 'anchor', 'ember', 'wolf',
             'harbor', 'ranger', 'shadow', 'meadow', 'castle', 'rocket', 'glacier', 'phoenix']

    def __init__(self, text, key):
        self.text = text
        self.key = key
        self._adj, self._noun = self._shuffled_lists()

    def _shuffled_lists(self):
        adj = self._ADJ[:]
        noun = self._NOUN[:]
        random.seed(str(self.key) + '::adj')
        random.shuffle(adj)
        random.seed(str(self.key) + '::noun')
        random.shuffle(noun)
        return adj, noun

    def encrypt(self):
        data = self.text.encode('utf-8')
        words = []
        for byte in data:
            hi, lo = byte >> 4, byte & 0x0F
            words.append(f'{self._adj[hi]}-{self._noun[lo]}')
        return '/MNEMONIC_CRYPTO ' + ' '.join(words)

    def decrypt(self):
        if '/MNEMONIC_CRYPTO ' not in self.text:
            return 'Padding error! /MNEMONIC_CRYPTO not found in the text'
        body = self.text.replace('/MNEMONIC_CRYPTO ', '')
        adj_rev = {w: i for i, w in enumerate(self._adj)}
        noun_rev = {w: i for i, w in enumerate(self._noun)}
        byte_vals = []
        for token in body.split(' '):
            a, _, n = token.partition('-')
            byte_vals.append((adj_rev[a] << 4) | noun_rev[n])
        return bytes(byte_vals).decode('utf-8')


# ========== TESTING ==========
if __name__ == "__main__":
    print("=== Testing Crypto (V1, fixed shift%26) ===")
    c1 = Crypto("hello world", 3)
    enc1 = c1.encrypt()
    print(f"Encrypted: {enc1}")
    dec1 = Crypto(enc1, 3).decrypt()
    print(f"Decrypted: {dec1}")
    assert dec1 == "hello world"

    print("\n=== Testing Substitution ===")
    c_sub = Crypto("hello world", 42)
    enc_sub = c_sub.substitution_encrypt()
    print(f"Encrypted: {enc_sub}")
    dec_sub = Crypto(enc_sub, 42).substitution_decrypt()
    print(f"Decrypted: {dec_sub}")
    assert dec_sub == "hello world"

    print("\n=== Testing CryptoV2 (fixed KeyError on unmapped chars) ===")
    c2 = CryptoV2("hello", "abcdefghijklmnopqrstuvwxyz")
    enc2 = c2.encrypt()
    print(f"Encrypted: {enc2}")
    dec2 = CryptoV2(enc2, "abcdefghijklmnopqrstuvwxyz").decrypt()
    print(f"Decrypted: {dec2}")
    assert dec2 == "hello"

    print("\n=== Testing Caesar Variation (fixed unicode wraparound) ===")
    c2c = CryptoV2("hello", 5)
    enc_caesar = c2c.caesar_variation_encrypt()
    print(f"Encrypted: {enc_caesar}")
    dec_caesar = CryptoV2(enc_caesar, 5).caesar_variation_decrypt()
    print(f"Decrypted: {dec_caesar}")
    assert dec_caesar == "hello"

    print("\n=== Testing CryptoV3Num (fixed decrypt check) ===")
    c3 = CryptoV3Num(12345, 3)
    enc3 = c3.encrypt()
    print(f"Encrypted: {enc3}")
    dec3 = CryptoV3Num(enc3, 3).decrypt()
    print(f"Decrypted: {dec3}")
    assert dec3 == "12345"

    print("\n=== Testing Rail Fence ===")
    c_rail = CryptoV3Num("hello123", 3)
    enc_rail = c_rail.rail_fence_encrypt()
    print(f"Encrypted: {enc_rail}")
    dec_rail = CryptoV3Num(enc_rail, 3).rail_fence_decrypt()
    print(f"Decrypted: {dec_rail}")
    assert dec_rail == "hello123"

    print("\n=== NEW: Testing CryptoV4XOR ===")
    c4 = CryptoV4XOR("hello world 123!", "s3cr3t-key")
    enc4 = c4.encrypt()
    print(f"Encrypted: {enc4}")
    dec4 = CryptoV4XOR(enc4, "s3cr3t-key").decrypt()
    print(f"Decrypted: {dec4}")
    assert dec4 == "hello world 123!"

    print("\n=== NEW: Testing CryptoV5Vigenere ===")
    c5 = CryptoV5Vigenere("Hello, World!", "lemon")
    enc5 = c5.encrypt()
    print(f"Encrypted: {enc5}")
    dec5 = CryptoV5Vigenere(enc5, "lemon").decrypt()
    print(f"Decrypted: {dec5}")
    assert dec5 == "Hello, World!"

    print("\n=== NEW: Testing CryptoV6Hash ===")
    h = CryptoV6Hash("hello world")
    digest = h.sha256()
    print(f"SHA256: {digest}")
    print(f"Verify: {h.verify(digest)}")
    assert h.verify(digest) is True

    print("\n=== NEW: Testing CryptoV7Atbash (keyed) ===")
    c7 = CryptoV7Atbash("Hello, World!", key=5)
    enc7 = c7.encrypt()
    print(f"Encrypted: {enc7}")
    dec7 = CryptoV7Atbash(enc7, key=5).decrypt()
    print(f"Decrypted: {dec7}")
    assert dec7 == "Hello, World!"

    print("\n=== NEW: Testing CryptoV8Morse ===")
    c8 = CryptoV8Morse("SOS HELP")
    enc8 = c8.encrypt()
    print(f"Encrypted: {enc8}")
    dec8 = CryptoV8Morse(enc8).decrypt()
    print(f"Decrypted: {dec8}")
    assert dec8 == "sos help"

    print("\n=== NEW: Testing CryptoV9RSAlite (educational only) ===")
    pub, priv = CryptoV9RSAlite.generate_keypair(61, 53)
    c9 = CryptoV9RSAlite("HI", key=pub)
    enc9 = c9.encrypt()
    print(f"Encrypted: {enc9}")
    dec9 = CryptoV9RSAlite(enc9, key=priv).decrypt()
    print(f"Decrypted: {dec9}")
    assert dec9 == "HI"

    print("\n=== NEW: Testing CryptoV10Emoji ===")
    c10 = CryptoV10Emoji("secret msg", key=7)
    enc10 = c10.encrypt()
    print(f"Encrypted: {enc10}")
    dec10 = CryptoV10Emoji(enc10, key=7).decrypt()
    print(f"Decrypted: {dec10}")
    assert dec10 == "secret msg"

    print("\n=== NEW: Testing FileCrypto ===")
    demo_path = 'demo_file.txt'
    with open(demo_path, 'w') as f:
        f.write("This is a demo file for FileCrypto testing.\nLine two.")

    fc = FileCrypto(demo_path)
    checksum = fc.sha256_checksum()
    print(f"SHA256 checksum: {checksum}")

    b64_path = fc.base64_encode_file()
    print(f"Base64 encoded -> {b64_path}")
    decoded_path = FileCrypto(b64_path).base64_decode_file(demo_path + '.roundtrip')
    with open(decoded_path, 'rb') as f:
        assert f.read() == open(demo_path, 'rb').read()
    print("Base64 file round-trip OK")

    fx = FileCrypto(demo_path, key='file-secret-key')
    xenc_path = fx.xor_encrypt_file()
    print(f"XOR encrypted -> {xenc_path}")
    xdec_path = FileCrypto(xenc_path, key='file-secret-key').xor_decrypt_file(demo_path + '.xroundtrip')
    with open(xdec_path, 'rb') as f:
        assert f.read() == open(demo_path, 'rb').read()
    print("XOR file round-trip OK")

    for p in [demo_path, b64_path, decoded_path, xenc_path, xdec_path]:
        if os.path.exists(p):
            os.remove(p)

    print("\n=== NEW: Testing CryptoV11DeepVault (text, random depth) ===")
    v1 = CryptoV11DeepVault("my-secret-key")
    print(f"Layer sequence: {v1.describe()}")
    blob = v1.encode("The treasure is buried under the old oak tree.")
    print(f"Encoded (truncated): {blob[:80]}...")
    v1_dec = CryptoV11DeepVault("my-secret-key", layers=v1.num_layers)
    restored = v1_dec.decode(blob)
    print(f"Decoded: {restored}")
    assert restored == "The treasure is buried under the old oak tree."

    print("\n=== NEW: Testing CryptoV11DeepVault (text, user-chosen depth) ===")
    v2 = CryptoV11DeepVault("another-key", layers=5)
    print(f"Layer sequence: {v2.describe()}")
    blob2 = v2.encode("short msg")
    dec2 = CryptoV11DeepVault("another-key", layers=5).decode(blob2)
    print(f"Decoded: {dec2}")
    assert dec2 == "short msg"

    print("\n=== NEW: Testing CryptoV11DeepVault (file, restores filename) ===")
    src_path = 'vault_demo.txt'
    with open(src_path, 'w') as f:
        f.write("Deep vault file contents.\nSecond line here.")
    vf = CryptoV11DeepVault("file-vault-key", layers=10)
    vault_path = vf.encode_file(src_path)
    print(f"Vault file -> {vault_path}")
    os.remove(src_path)  # prove it gets restored from inside the vault
    restored_path = CryptoV11DeepVault("file-vault-key", layers=10).decode_file(vault_path)
    print(f"Restored -> {restored_path}")
    with open(restored_path, 'r') as f:
        content = f.read()
    assert content == "Deep vault file contents.\nSecond line here."
    for p in [vault_path, restored_path]:
        if os.path.exists(p):
            os.remove(p)
    print("Deep vault file round-trip OK (original filename auto-restored)")

    print("\n=== Testing KeyGenerator ===")
    print(f"Key v1: {KeyGenerator.key_generator_num_v1(1, 10)}")
    print(f"Key v2: {KeyGenerator.key_generator_num_v2(10)}")
    print(f"NEW Password: {KeyGenerator.key_generator_password(16)}")

    print("\nAll tests passed ✅")