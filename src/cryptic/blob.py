import typing

from cryptic.lazy import Lazy


@typing.final
class Blob:
    __slots__ = ("_bytes", "_bits", "_hex")

    def __init__(self, data: "bytes | Blob"):
        self._bytes = (
            data.bytes if isinstance(data, Blob) else _typecheck(data, bytes)
        )
        self._bits = Lazy(lambda: "".join(map(_format_byte, self._bytes)))
        self._hex = Lazy(lambda: self._bytes.hex())

    @property
    def bytes(self) -> bytes:
        return self._bytes

    @property
    def bits(self) -> str:
        return self._bits.value

    @property
    def hex(self) -> str:
        return self._hex.value

    def bit_len(self) -> int:
        return self.byte_len() << 3

    def byte_len(self) -> int:
        return len(self.bytes)

    def __hash__(self) -> int:
        return hash(self.bytes)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Blob) and self.bytes == other.bytes

    def __repr__(self) -> str:
        return f"{type(self).__name__}({repr(self.bytes)})"

    def __str__(self) -> str:
        return repr(self)


def _typecheck[T](value: T, klass: type[T]) -> T:
    assert isinstance(value, klass)
    return value


def _format_byte(byte: int) -> str:
    assert 0 <= byte < 256
    return format(byte, "08b")
