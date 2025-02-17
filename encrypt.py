import argparse
import sys
import os
import random


def encrypt(file):
    with open(file, "rb") as f:
        data = f.read(-1)

    key = random.randbytes(1)[0]
    data = bytes(b ^ key for b in data)

    suffix = os.path.splitext(file)[1]
    suffixbytes = suffix.encode() + b'\0' * (8 - len(suffix.encode()))

    with open(file.replace(suffix, ".bin"), "wb") as f:
        f.write(bytes([key]))
        f.write(data)
        f.write(suffixbytes)

    print(f"Contents written to {file.replace(suffix, '.bin')}!")


def decrypt(file):
    with open(file, "rb") as f:
        data = f.read(-1)

    key = data[0]

    suffix = data[-8:].split(b'\0')[0].decode()

    data = data[1:-8]
    data = bytes(b ^ key for b in data)

    with open(file.replace(".bin", suffix), "wb") as f:
        f.write(data)

    print(f"Contents written to {file.replace('.bin', suffix)}!")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation")
    parser.add_argument("file")

    args = parser.parse_args(sys.argv[1:])

    if args.operation == "encrypt":
        return encrypt(args.file)
    if args.operation == "decrypt":
        return decrypt(args.file)

    raise Exception(f"Unknown operation {args.operation}")


if __name__ == '__main__':
    main()

