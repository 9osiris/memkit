"""Pointer chain resolution: base address plus a list of offsets."""


def resolve(process, base_address, offsets):
    """Walk a pointer chain and return the final address.

    base_address holds a pointer. Each offset except the last is added and
    then dereferenced. The last offset is added without a final dereference,
    so resolve(proc, base, [0x10, 0x20]) means *(*(base) + 0x10) + 0x20.
    """
    offsets = list(offsets)
    addr = process.read_pointer(base_address)
    for off in offsets[:-1]:
        addr = process.read_pointer(addr + off)
    if offsets:
        addr += offsets[-1]
    return addr
