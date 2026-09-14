import sys
from pathlib import Path

def xor_bytes(data: bytes, key: int = 0xAA) -> bytes:
    return bytes(b ^ key for b in data)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} <input> <output>", file=sys.stderr)
        return 1

    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    dst.write_bytes(xor_bytes(src.read_bytes()))
    return 0

if __name__ == "__main__":
    sys.exit(main())