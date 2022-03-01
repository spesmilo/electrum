class Token:
    def __init__(self, token_id: int, symbol: str, decimal: int, **attrs):
        self._attrs = attrs
        self.token_id = token_id
        self.symbol = symbol
        self.decimal = decimal

    def __getitem__(self, key):
        if hasattr(self, key):
            return getattr(self, key)
        return self._attrs[key]

    def __setitem__(self, key, value):
        self._attrs[key] = value

    def __str__(self):
        return f"{self.symbol}#{self.token_id}"
