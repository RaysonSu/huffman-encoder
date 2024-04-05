from __future__ import annotations

from sys import argv, hash_info
from typing import Generic, TypeVar

FILE: str = argv[0]
MAX_HASH: int = 2 ** hash_info.hash_bits
TREE_TERMINATOR: bytes = b"\x80"
EOT_TERMINATOR: bytes = b"\x81"
T = TypeVar('T')


class Node(Generic[T]):
    def __init__(self, value: T | None = None, children: list[Node[T]] | None = None) -> None:
        self.value: T | None = value
        self.children: list[Node[T]] = []

        if children:
            self.children = children

    def __hash__(self) -> int:
        ret: int = 413612

        ret += hash(self.value) * 111111
        ret %= MAX_HASH
        for value in self.children:
            ret *= 612413
            ret += hash(value)
            ret %= MAX_HASH

        return ret

    def __str__(self) -> str:
        ret: str = f""

        if self.value:
            ret += f"({self.value})"
        else:
            ret += "()"

        if self.children:
            ret += f"-[{', '.join(map(str, self.children))}]"

        return ret


def encode_tree(tree: Node[str]) -> bytes:
    # this only works when all children of this tree are either
    # 1. have two children and no value, or
    # 2. have no children and a character as value

    if tree.children:
        return encode_tree(tree.children[0]) + \
            encode_tree(tree.children[1]) + \
            TREE_TERMINATOR
    else:
        return str(tree.value)[0].encode()


def decode_tree(data: bytearray) -> tuple[Node[str], bytearray]:
    stack: list[Node[str]] = []

    while data[0] != ord(EOT_TERMINATOR):
        value: int = data.pop(0)
        if value == ord(TREE_TERMINATOR):
            right: Node[str] = stack.pop()
            left: Node[str] = stack.pop()

            stack.append(Node(children=[left, right]))
        else:
            stack.append(Node(chr(value)))

    data.pop(0)  # removes the end of tree terminator

    return stack[0], data


def codeify(tree: Node[str]) -> dict[str, str]:
    ret: dict[str, str] = {}
    if tree.value:
        ret[tree.value] = ""

    for i, child in enumerate(tree.children):
        for key, encoded in codeify(child).items():
            ret[key] = str(i) + encoded

    return ret


def treeify(frequency: list[tuple[str, int]]) -> Node[str]:
    tree_remaining: list[tuple[int, int, Node]] = []
    unique_id: int = 0

    for key, value in frequency:
        tree_remaining.append((value, unique_id, Node(key)))
        unique_id += 1

    unique_id = -1
    while len(tree_remaining) > 1:
        tree_remaining.sort()
        # print("\n" * 100 + "\033[H\033[3J", end="")
        # for freq, _, node in tree_remaining:
        #     print(f"[{freq}, {_}] {node}")
        # input()

        left_amount: int
        left_value: Node[str]
        right_amount: int
        right_value: Node[str]

        left_amount, _, left_value = tree_remaining.pop(0)
        right_amount, _, right_value = tree_remaining.pop(0)

        tree_remaining.append((
            left_amount + right_amount,
            unique_id,
            Node(children=[left_value, right_value])
        ))
        unique_id -= 1
    # print("\n" * 100 + "\033[H\033[3J", end="")
    # print(f"[{tree_remaining[0][0]}] {tree_remaining[0][2]}")
    return tree_remaining[0][2]


def frequency_count(string: str) -> list[tuple[str, int]]:
    ret: list[tuple[str, int]] = []

    while string:
        char = string[0]
        ret.append((char, string.count(char)))
        string = string.replace(char, "")

    return ret


def encode_file(input_path: str, destination_path: str) -> None:
    # file format:
    # 3 bytes at the start to encode the length
    # representation of the huffman tree
    # huffman encoding

    with open(input_path, "r") as file:
        data: str = file.read()
        huffman_tree: Node[str] = treeify(frequency_count(data))
        huffman_tree_encoding: bytes = encode_tree(huffman_tree)
        encoding: dict[str, str] = codeify(huffman_tree)

    with open(destination_path, "xb") as file:
        file.write(len(data).to_bytes(3))
        file.write(huffman_tree_encoding)
        file.write(EOT_TERMINATOR)
        buffer: int = 1
        for char in data:
            for bit in encoding[char]:
                buffer <<= 1
                buffer |= int(bit)

                if buffer & 0x100:
                    file.write((buffer & 0xff).to_bytes())
                    buffer >>= 8

        while not buffer & 0x100:
            buffer <<= 1
        
        file.write((buffer & 0xff).to_bytes())

def decode_file(input_path: str, destination_path: str) -> None:
    with open(input_path, "rb") as file:
        chars: int = int.from_bytes(file.read(3))

        tree: Node[str]
        encoding: bytearray
        tree, encoding = decode_tree(bytearray(file.read()))

    
    with open(destination_path, "x") as file:
        data: str = ""
        bit: int = 0

        for _ in range(chars):
            cur_node: Node[str] = tree
            bits_read: str = ""
            while not cur_node.value:
                byte: int = bit // 8
                bit_index: int = bit & 0x7
                read_bit: int = ((encoding[byte] << bit_index) & 0x80) >> 7
                bits_read += str(read_bit)
                cur_node = cur_node.children[read_bit]
                bit += 1
            
            data += cur_node.value
        
        file.write(data)

def main():
    if argv[1].lower() in ["e", "encode"]:
        encode_file(argv[2], argv[3])
        return 0
    
    if argv[1].lower() in ["d", "decode"]:
        decode_file(argv[2], argv[3])
        return 0

    raise ValueError(f"No such mode: {argv[1]}")

if __name__ == "__main__":
    main()
