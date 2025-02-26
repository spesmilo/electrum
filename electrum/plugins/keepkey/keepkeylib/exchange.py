from protobuf3.fields import Int64Field, MessageField, UInt64Field, BytesField, StringField
from protobuf3.message import Message


class ExchangeAddress(Message):
    pass


class ExchangeResponseV2(Message):
    pass


class SignedExchangeResponse(Message):
    pass


class ExchangeResponse(Message):
    pass

ExchangeAddress.add_field('coin_type', StringField(field_number=1, optional=True))
ExchangeAddress.add_field('address', StringField(field_number=2, optional=True))
ExchangeAddress.add_field('dest_tag', StringField(field_number=3, optional=True))
ExchangeAddress.add_field('rs_address', StringField(field_number=4, optional=True))
ExchangeResponseV2.add_field('deposit_address', MessageField(field_number=1, optional=True, message_cls=ExchangeAddress))
ExchangeResponseV2.add_field('deposit_amount', BytesField(field_number=2, optional=True))
ExchangeResponseV2.add_field('expiration', Int64Field(field_number=3, optional=True))
ExchangeResponseV2.add_field('quoted_rate', BytesField(field_number=4, optional=True))
ExchangeResponseV2.add_field('withdrawal_address', MessageField(field_number=5, optional=True, message_cls=ExchangeAddress))
ExchangeResponseV2.add_field('withdrawal_amount', BytesField(field_number=6, optional=True))
ExchangeResponseV2.add_field('return_address', MessageField(field_number=7, optional=True, message_cls=ExchangeAddress))
ExchangeResponseV2.add_field('api_key', BytesField(field_number=8, optional=True))
ExchangeResponseV2.add_field('miner_fee', BytesField(field_number=9, optional=True))
ExchangeResponseV2.add_field('order_id', BytesField(field_number=10, optional=True))
SignedExchangeResponse.add_field('response', MessageField(field_number=1, optional=True, message_cls=ExchangeResponse))
SignedExchangeResponse.add_field('signature', BytesField(field_number=2, optional=True))
SignedExchangeResponse.add_field('responseV2', MessageField(field_number=3, optional=True, message_cls=ExchangeResponseV2))
ExchangeResponse.add_field('deposit_address', MessageField(field_number=1, optional=True, message_cls=ExchangeAddress))
ExchangeResponse.add_field('deposit_amount', UInt64Field(field_number=2, optional=True))
ExchangeResponse.add_field('expiration', Int64Field(field_number=3, optional=True))
ExchangeResponse.add_field('quoted_rate', UInt64Field(field_number=4, optional=True))
ExchangeResponse.add_field('withdrawal_address', MessageField(field_number=5, optional=True, message_cls=ExchangeAddress))
ExchangeResponse.add_field('withdrawal_amount', UInt64Field(field_number=6, optional=True))
ExchangeResponse.add_field('return_address', MessageField(field_number=7, optional=True, message_cls=ExchangeAddress))
ExchangeResponse.add_field('api_key', BytesField(field_number=8, optional=True))
ExchangeResponse.add_field('miner_fee', UInt64Field(field_number=9, optional=True))
ExchangeResponse.add_field('order_id', BytesField(field_number=10, optional=True))
