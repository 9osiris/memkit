"""Dump a memory region to a file."""


def dump_region(process, start, size, path, chunk_size=1 << 16):
    """Read [start, start+size) and write it to path. Returns the path."""
    with open(path, "wb") as f:
        addr = start
        left = size
        while left > 0:
            n = min(chunk_size, left)
            f.write(process.read(addr, n))
            addr += n
            left -= n
    return path
