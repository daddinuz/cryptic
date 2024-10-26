import base58
import enum
import hashlib
import hmac
import secrets
import typing

from collections import abc
from cryptic.blob import Blob


type EntropyGenerator = typing.Callable[[int], bytes]


@enum.unique
class Strength(enum.Enum):
    MIN = 128
    LOW = 160
    MEDIUM = 192
    HIGH = 224
    MAX = 256


@typing.final
class Entropy:
    __slots__ = ("_blob",)

    def __init__(self, data: bytes | Blob):
        blob = Blob(data)
        assert (blob.byte_len() << 3) in Strength
        self._blob = blob

    @classmethod
    def new(
        cls,
        strength: Strength,
        generator: EntropyGenerator = secrets.token_bytes,
    ) -> "Entropy":
        return cls(generator(strength.value << 3))

    @property
    def blob(self) -> Blob:
        return self._blob

    def __hash__(self) -> int:
        return hash(self.blob)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.blob == other.blob

    def __repr__(self) -> str:
        return f"{type(self).__name__}({repr(self.blob.bytes)})"

    def __str__(self) -> str:
        return repr(self)


@typing.final
class Checksum:
    """
    first (entropy length / 32) bits of its SHA256 hash
    """

    __slots__ = ("_bits",)

    def __init__(self, bits: str):
        assert 4 <= len(bits) <= 8
        assert all(map(lambda c: c in "01", bits))
        self._bits = bits

    @classmethod
    def new(cls, entropy: Entropy) -> "Checksum":
        bit_len = len(entropy.blob.bytes) >> 2
        value = hashlib.sha256(entropy.blob.bytes).digest()[0] >> (8 - bit_len)
        bits = format(value, "b").zfill(bit_len)
        return cls(bits)

    @property
    def bits(self) -> str:
        return self._bits

    def bit_len(self) -> int:
        return len(self.bits)

    def __hash__(self) -> int:
        return hash(self.bits)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.bits == other.bits

    def __repr__(self) -> str:
        return f"{type(self).__name__}({repr(self.bits)})"

    def __str__(self) -> str:
        return repr(self)


@typing.final
class WordList(abc.Sequence[str]):
    __slots__ = ("_words",)

    def __init__(self, words: abc.Sequence[str]):
        assert len(words) == 2048
        self._words = words

    @classmethod
    def read(cls, path: str) -> "WordList":
        with open(path) as file:
            return cls([line.strip() for line in file])

    @typing.overload
    def __getitem__(self, index: int) -> str: ...

    @typing.overload
    def __getitem__(self, index: slice) -> abc.Sequence[str]: ...

    @typing.override
    def __getitem__(self, index: int | slice) -> str | abc.Sequence[str]:
        return self._words[index]

    @typing.override
    def __len__(self) -> int:
        return len(self._words)

    def __hash__(self) -> int:
        return hash(self._words)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self._words == other._words

    def __repr__(self) -> str:
        return f"{type(self).__name__}({repr(self._words)})"

    def __str__(self) -> str:
        return repr(self)


@typing.final
class Mnemonic(abc.Sequence[str]):
    __slots__ = ("_words",)

    def __init__(self, words: abc.Sequence[str]):
        self._words = words

    @classmethod
    def new(cls, wordlist: WordList, entropy: Entropy) -> "Mnemonic":
        checksum = Checksum.new(entropy)
        entropy_with_checksum = entropy.blob.bits + checksum.bits
        return cls(
            [
                wordlist[int(entropy_with_checksum[pos : pos + 11], 2)]
                for pos in range(0, len(entropy_with_checksum), 11)
            ]
        )

    @typing.overload
    def __getitem__(self, index: int) -> str: ...

    @typing.overload
    def __getitem__(self, index: slice) -> abc.Sequence[str]: ...

    @typing.override
    def __getitem__(self, index: int | slice) -> str | abc.Sequence[str]:
        return self._words[index]

    @typing.override
    def __len__(self) -> int:
        return len(self._words)

    def __hash__(self) -> int:
        return hash(self._words)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self._words == other._words

    def __repr__(self) -> str:
        return f"{type(self).__name__}({repr(self._words)})"

    def __str__(self) -> str:
        return repr(self)


@typing.final
class Seed:
    __slots__ = ("_blob",)

    def __init__(self, data: bytes | Blob):
        blob = Blob(data)
        assert blob.byte_len() in (16, 32, 64)
        self._blob = blob

    @classmethod
    def new(cls, mnemonic: Mnemonic, passphrase: str = "") -> "Seed":
        password = " ".join(mnemonic).encode()
        salt = f"mnemonic{passphrase}".encode()
        return Seed(hashlib.pbkdf2_hmac("sha512", password, salt, 2048))

    @property
    def blob(self) -> Blob:
        return self._blob

    def __hash__(self) -> int:
        return hash(self.blob)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.blob == other.blob

    def __repr__(self) -> str:
        return f"{type(self).__name__}({repr(self.blob.bytes)})"

    def __str__(self) -> str:
        return repr(self)


@typing.final
class MasterChainCode:
    __slots__ = ("_blob",)

    def __init__(self, data: bytes | Blob):
        blob = Blob(data)
        assert blob.byte_len() == 32
        self._blob = blob

    @property
    def blob(self) -> Blob:
        return self._blob

    def __hash__(self) -> int:
        return hash(self.blob)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.blob == other.blob

    def __repr__(self) -> str:
        return f"{type(self).__name__}({repr(self.blob.bytes)})"

    def __str__(self) -> str:
        return repr(self)


@enum.unique
class KeyVersionBytes(enum.Enum):
    MAINNET_PUBLIC = bytes.fromhex("0488B21E")
    MAINNET_PRIVATE = bytes.fromhex("0488ADE4")
    TESTNET_PUBLIC = bytes.fromhex("043587CF")
    TESTNET_PRIVATE = bytes.fromhex("04358394")


@enum.unique
class Net(enum.Enum):
    MAINNET = "mainnet"
    TESTNET = "testnet"


@typing.final
class MasterPrivateKey:
    __slots__ = ("_chain_code", "_net", "_blob")

    def __init__(
        self, chain_code: MasterChainCode, net: Net, data: bytes | Blob
    ):
        blob = Blob(data)
        kn = int.from_bytes(blob.bytes, "big")
        assert (
            0
            < kn
            < 115792089237316195423570985008687907852837564279074904382605163141518161494337
        )
        self._chain_code = chain_code
        self._net = net
        self._blob = blob

    @classmethod
    def new(cls, seed: Seed, net: Net) -> "MasterPrivateKey":
        digest = hmac.HMAC(
            "Bitcoin seed".encode(),
            msg=seed.blob.bytes,
            digestmod=hashlib.sha512,
        ).digest()
        master_private_key, master_chain_code = digest[:32], digest[32:]
        return cls(MasterChainCode(master_chain_code), net, master_private_key)

    def serialize(self):
        out = (
            KeyVersionBytes.MAINNET_PRIVATE
            if self.net is Net.MAINNET
            else KeyVersionBytes.TESTNET_PRIVATE
        ).value
        out += b"\x00" * 9
        out += self.chain_code.blob.bytes
        out += b"\x00" + self.blob.bytes
        return base58.b58encode_check(out)

    @property
    def chain_code(self) -> MasterChainCode:
        return self._chain_code

    @property
    def net(self) -> Net:
        return self._net

    @property
    def blob(self) -> Blob:
        return self._blob

    def __hash__(self) -> int:
        return hash((self.chain_code, self.net, self.blob))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, type(self))
            and self.chain_code == other.chain_code
            and self.net == other.net
            and self.blob == other.blob
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}({repr(self.chain_code)}, {repr(self.net)}, {repr(self.blob.bytes)})"

    def __str__(self) -> str:
        return repr(self)
