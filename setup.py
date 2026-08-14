from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cryptodo",
    version="3.3.1",
    author="K.A. Ishan Oshada",
    author_email="ic31908@gmail.com",
    description="A comprehensive Python library for text encryption, decryption, and cryptographic operations with 20+ cipher methods",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ishanoshada/cryptodo",
    project_urls={
        "Bug Reports": "https://github.com/ishanoshada/cryptodo/issues",
        "Source": "https://github.com/ishanoshada/cryptodo",
        "Documentation": "https://github.com/ishanoshada/cryptodo#readme",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Topic :: Security :: Cryptography",
        "Topic :: Education",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords=[
        "encryption", "decryption", "cryptography", "cipher",
        "caesar-cipher", "vigenere-cipher", "substitution-cipher",
        "rail-fence-cipher", "playfair-cipher", "hill-cipher",
        "adfgvx-cipher", "autokey-cipher", "xor-cipher",
        "steganography", "zero-width", "braille", "mnemonic",
        "hash", "checksum", "security", "crypto"
    ],
    python_requires=">=3.6",
    license="MIT",
    platforms=["any"],
    zip_safe=False,
)