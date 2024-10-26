import typing


type _FactoryMethod[T] = typing.Callable[[], T]


@typing.final
class Lazy[T]:
    __slots__ = ("_value",)

    def __init__(self, factory: _FactoryMethod[T]):
        self._value = self._Factory(factory)

    @property
    def value(self) -> T:
        if isinstance(self._value, self._Factory):
            self._value = self._value()
        return self._value

    class _Factory:
        __slots__ = ("_factory",)

        def __init__(self, factory: _FactoryMethod[T]):
            self._factory = factory

        def __call__(self) -> T:
            return self._factory()
