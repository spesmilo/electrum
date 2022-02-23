import asyncio
from asyncio import Queue
from typing import Dict, NamedTuple, Optional
from unittest import TestCase


async def peer(
        is_initiator: bool,
        send_queue: Queue,
        receive_queue: Queue,
        fee_range: Optional[Dict],
        our_fee: int,
):
    def print_named(text):
        print(f"{'A' if is_initiator else 'B'}: " + text)

    cycles = 0
    their_fee = None

    fee_range_sent = {}

    async def send_closing_signed():
        MODERN_FEE = True
        if MODERN_FEE:
            nonlocal fee_range_sent  # we change fee_range_sent in outer scope
            fee_range_sent = fee_range
            await send_queue.put({'fee_satoshis': our_fee, 'fee_range': fee_range_sent})
        else:
            await send_queue.put({'fee_satoshis': our_fee, 'fee_range': {}})

    if is_initiator:
        await send_closing_signed()

    # negotiate fee
    while True:
        cycles += 1
        cs_payload = await receive_queue.get()

        their_previous_fee = their_fee
        their_fee = cs_payload['fee_satoshis']

        # 0. integrity checks
        # skipped

        # 1. check fees
        # if fee_satoshis is equal to its previously sent fee_satoshis:
        if our_fee == their_fee:
            # SHOULD sign and broadcast the final closing transaction.
            break  # we publish

        # 2. at start, adapt our fee range if we are not the channel initiator
        fee_range_received = cs_payload['fee_range']
        print_named(f"Received fee range: {fee_range_received} and fee: {their_fee}")
        # The sending node: if it is not the funder:
        if fee_range_received and not is_initiator and not fee_range_sent:
            # SHOULD set max_fee_satoshis to at least the max_fee_satoshis received
            fee_range['max_fee_satoshis'] = max(fee_range_received['max_fee_satoshis'], fee_range['max_fee_satoshis'])
            # SHOULD set min_fee_satoshis to a fairly low value
            # TODO: what's a fairly low value? allows the initiator to go to low values
            fee_range['min_fee_satoshis'] = min(fee_range_received['min_fee_satoshis'], fee_range['min_fee_satoshis'])  # maximal collaboration
            # fee_range['min_fee_satoshis'] = fee_range['min_fee_satoshis'] // 2  # just lower our minimal fee a bit

        # 3. if fee_satoshis matches its previously sent fee_range:
        if fee_range_sent and (fee_range_sent['min_fee_satoshis'] <= their_fee <= fee_range_sent['max_fee_satoshis']):
            # SHOULD reply with a closing_signed with the same fee_satoshis value if it is different from its previously sent fee_satoshis
            if our_fee != their_fee:
                our_fee = their_fee
                await send_closing_signed()  # peer publishes
                break
            # SHOULD use `fee_satoshis` to sign and broadcast the final closing transaction
            else:
                our_fee = their_fee
                break  # we publish

        # 4. if the message contains a fee_range
        if fee_range_received:
            overlap_min = max(fee_range['min_fee_satoshis'], fee_range_received['min_fee_satoshis'])
            overlap_max = min(fee_range['max_fee_satoshis'], fee_range_received['max_fee_satoshis'])
            # if there is no overlap between that and its own fee_range
            if overlap_min > overlap_max:
                raise Exception("There is no overlap between between their and our fee range.")
                # TODO: MUST fail the channel if it doesn't receive a satisfying fee_range after a reasonable amount of time
            # otherwise:
            else:
                if is_initiator:
                    # if fee_satoshis is not in the overlap between the sent and received fee_range:
                    if not (overlap_min <= their_fee <= overlap_max):
                        # MUST fail the channel
                        raise Exception("Their fee is not in the overlap region, we force closed.")
                    # otherwise:
                    else:
                        our_fee = their_fee
                        # MUST reply with the same fee_satoshis.
                        await send_closing_signed()  # peer publishes
                        break
                # otherwise (it is not the funder):
                else:
                    # if it has already sent a closing_signed:
                    if fee_range_sent:
                        # if fee_satoshis is not the same as the value it sent:
                        if their_fee != our_fee:
                            # MUST fail the channel
                            raise Exception("Expected the same fee as ours, we force closed.")
                    # otherwise:
                    else:
                        # MUST propose a fee_satoshis in the overlap between received and (about-to-be) sent fee_range.
                        our_fee = (overlap_min + overlap_max) // 2
                        await send_closing_signed()
                        continue
        # otherwise, if fee_satoshis is not strictly between its last-sent fee_satoshis
        # and its previously-received fee_satoshis, UNLESS it has since reconnected:
        elif their_previous_fee and not (min(our_fee, their_previous_fee) < their_fee < max(our_fee, their_previous_fee)):
            # SHOULD fail the connection.
            raise Exception('Their fee is not between our last sent and their last sent fee.')
        # otherwise, if the receiver agrees with the fee:
        elif abs(their_fee - our_fee) <= 1:  # we cannot have another strictly in-between value
            # SHOULD reply with a closing_signed with the same fee_satoshis value.
            our_fee = their_fee
            await send_closing_signed()  # peer publishes
            break
        # otherwise:
        else:
            # MUST propose a value "strictly between" the received fee_satoshis and its previously-sent fee_satoshis.
            our_fee = (our_fee + their_fee) // 2
            await send_closing_signed()

    # reaching this part of the code means that we have reached agreement; to make
    # sure the peer doesn't force close, send a last closing_signed
    if not is_initiator:
        await send_closing_signed()

    print_named(f"agree {our_fee} {their_fee}, I'm signing and broadcasting")
    return our_fee, cycles


async def main(initiator_fee, initiator_fee_range, receiver_fee, receiver_fee_range):
    queue1 = Queue(maxsize=1)
    queue2 = Queue(maxsize=1)
    worker1 = peer(is_initiator=True, send_queue=queue1, receive_queue=queue2, fee_range=initiator_fee_range, our_fee=initiator_fee)
    worker2 = peer(is_initiator=False, send_queue=queue2, receive_queue=queue1, fee_range=receiver_fee_range, our_fee=receiver_fee)
    return await asyncio.gather(worker1, worker2)


class TestNegotiation(TestCase):

    def test_legacy_ini_low(self):
        """legacy fee negotiation"""
        inititator, receiver = asyncio.run(main(initiator_fee=100, receiver_fee=150, initiator_fee_range={}, receiver_fee_range={}))
        self.assertTrue(inititator[0] == receiver[0] == 116)
        self.assertEqual(3, inititator[1])
        self.assertEqual(4, receiver[1])

    def test_legacy_ini_high(self):
        """legacy fee negotiation"""
        inititator, receiver = asyncio.run(main(initiator_fee=2000, receiver_fee=100, initiator_fee_range={}, receiver_fee_range={}))
        self.assertTrue(inititator[0] == receiver[0] == 1365)
        self.assertEqual(6, inititator[1])
        self.assertEqual(7, receiver[1])

    def test_modern_ini_low_fee_range(self):
        inititator, receiver = asyncio.run(
            main(initiator_fee=1, receiver_fee=200,
                 initiator_fee_range={'min_fee_satoshis': 1, 'max_fee_satoshis': 10},
                 receiver_fee_range={'min_fee_satoshis': 10, 'max_fee_satoshis': 300}))
        self.assertTrue(inititator[0] == receiver[0] == 5)
        self.assertEqual(1, inititator[1])
        self.assertEqual(2, receiver[1])

    def test_modern_no_initial_overlap(self):
        # fails, because non-initiator accepts low fee range bound
        # self.assertRaises(Exception, lambda: asyncio.run(
        #     main(initiator_fee=1, receiver_fee=200,
        #          initiator_fee_range={'min_fee_satoshis': 1, 'max_fee_satoshis': 10},
        #          receiver_fee_range={'min_fee_satoshis': 50, 'max_fee_satoshis': 300})))

        # succeeds, because non-initiator accepts low fee range bound
        inititator, receiver = asyncio.run(
            main(initiator_fee=1, receiver_fee=200,
                 initiator_fee_range={'min_fee_satoshis': 1, 'max_fee_satoshis': 10},
                 receiver_fee_range={'min_fee_satoshis': 50, 'max_fee_satoshis': 300}))
        self.assertTrue(inititator[0] == receiver[0] == 5)
        self.assertEqual(1, inititator[1])
        self.assertEqual(2, receiver[1])

    def test_modern_fee_range_overlap(self):
        inititator, receiver = asyncio.run(main(
            initiator_fee=100, receiver_fee=200,
            initiator_fee_range={'min_fee_satoshis': 100, 'max_fee_satoshis': 300},
            receiver_fee_range={'min_fee_satoshis': 50, 'max_fee_satoshis': 200}))
        self.assertTrue(inititator[0] == receiver[0] == 200)
        self.assertEqual(1, inititator[1])
        self.assertEqual(2, receiver[1])

    def test_modern_fee_range_overlap_swapped(self):
        inititator, receiver = asyncio.run(main(
            receiver_fee=100, initiator_fee=200,
            initiator_fee_range={'min_fee_satoshis': 50, 'max_fee_satoshis': 200},
            receiver_fee_range={'min_fee_satoshis': 100, 'max_fee_satoshis': 300}))
        self.assertTrue(inititator[0] == receiver[0] == 125)
        self.assertEqual(1, inititator[1])
        self.assertEqual(2, receiver[1])
