# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import threading
import weakref
from typing import TYPE_CHECKING, Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Union

from . import util
from .i18n import _
from .logging import Logger
from .util import EventListener, event_listener, UserFacingException
from .transaction import PartialTxInput, TxOutpoint
from .address_synchronizer import TX_HEIGHT_FUTURE

if TYPE_CHECKING:
    from .wallet import Abstract_Wallet
    from .transaction import Transaction


CoinType = Union[str, TxOutpoint, PartialTxInput]


def outpoint_str(coin: CoinType) -> str:
    if isinstance(coin, str):
        return coin
    if isinstance(coin, TxOutpoint):
        return coin.to_str()
    if isinstance(coin, PartialTxInput):
        return coin.prevout.to_str()
    raise TypeError(f"cannot interpret {type(coin)} as a coin")


class CoinControlStatus(NamedTuple):
    is_active: bool
    num_selected: int  # selected outpoints that are still unspent
    num_usable: int    # selected AND passing the policy filters
    num_total: int     # all wallet utxos
    value_sat: int     # sum of the usable ones


class CoinFilter(Logger, EventListener):
    """Owns the decision of which coins are usable/spendable.

    Three layers, applied in this order:
      1. existence:   is it an unspent is_mine utxo?  (delegated to adb)
      2. policy:      frozen addr/coin, maturity, confirmed_only, nonlocal_only
      3. user intent: `domain`, and the manual "coin control" selection

    The selection is stored as bare outpoint strings and is combined with
    the live policy-filtered utxo set on every read.
    """

    def __init__(self, wallet: 'Abstract_Wallet'):
        # weak ref. we are owned by the wallet, so we must not keep it alive
        self._wallet = weakref.ref(wallet)
        Logger.__init__(self)
        self.db = wallet.db
        self.config = wallet.config
        self.lock = threading.RLock()

        self._frozen_addresses = set(self.db.get('frozen_addresses', []))
        self._frozen_coins = self.db.get_dict('frozen_coins')  # type: Dict[str, bool]

        # coin control. in-memory only.
        self._selection = set()  # type: Set[str]

        self.register_callbacks()

    @property
    def wallet(self) -> 'Abstract_Wallet':
        wallet = self._wallet()
        if wallet is None:
            raise RuntimeError("CoinFilter used after its wallet was garbage-collected")
        return wallet

    def diagnostic_name(self):
        # must not raise.
        wallet = self._wallet()
        return wallet.diagnostic_name() if wallet is not None else ""

    def stop(self) -> None:
        self.unregister_callbacks()

    @property
    def adb(self):
        return self.wallet.adb

    def get_utxos(self, domain: Optional[Iterable[str]] = None, **kwargs) -> Sequence[PartialTxInput]:
        if domain is None:
            domain = self.wallet.get_addresses()
        return self.adb.get_utxos(domain=domain, **kwargs)

    def get_spendable_coins(
            self,
            domain: Optional[Iterable[str]] = None,
            *,
            nonlocal_only: bool = False,
            confirmed_only: bool = None,
            ignore_coin_control: bool = False,
    ) -> Sequence[PartialTxInput]:
        """The coins we are allowed to spend.

        confirmed_only: tri-state, None defers to config
        ignore_coin_control: skip the user's manual selection.
        """
        with self.lock:
            frozen_addresses = self._frozen_addresses.copy()
            selection = None if ignore_coin_control else self._selection.copy()
        if confirmed_only is None:
            confirmed_only = self.config.WALLET_SPEND_CONFIRMED_ONLY
        utxos = self.get_utxos(
            domain=domain,
            excluded_addresses=frozen_addresses,
            mature_only=True,
            confirmed_funding_only=confirmed_only,
            nonlocal_only=nonlocal_only,
        )
        utxos = [utxo for utxo in utxos if not self.is_frozen_coin(utxo)]
        if selection:
            # note: compose with the filters above, never replace them. this is
            # what keeps a coin that was frozen *after* being selected, or one
            # excluded by confirmed_only/nonlocal_only, out of the spend set.
            utxos = [utxo for utxo in utxos if utxo.prevout.to_str() in selection]
        return utxos

    def get_coins_for_outpoints(
            self,
            outpoints: Iterable[CoinType],
            *,
            domain: Optional[Iterable[str]] = None,
            **kwargs,
    ) -> Sequence[PartialTxInput]:
        """Resolve an explicit list of outpoints to spendable coins.

        Used for one-shot overrides such as the CLI's --from_coins. Ignores
        any stored coin control selection. Raises if an outpoint is unknown
        or unspendable. Duplicates are dropped, keeping first-seen order:
        returning a coin twice would build a tx spending it twice.
        """
        wanted = []  # type: List[str]
        seen = set()  # type: Set[str]
        for op in outpoints:
            op = outpoint_str(op)
            if op not in seen:
                seen.add(op)
                wanted.append(op)
        coins = self.get_spendable_coins(domain, ignore_coin_control=True, **kwargs)
        by_outpoint = {coin.prevout.to_str(): coin for coin in coins}
        for op in wanted:
            if op not in by_outpoint:
                raise UserFacingException(
                    _("Unknown or unspendable coin: {}").format(op))
        return [by_outpoint[op] for op in wanted]

    def is_frozen_address(self, addr: str) -> bool:
        return addr in self._frozen_addresses

    def is_frozen_coin(self, utxo: PartialTxInput) -> bool:
        prevout_str = utxo.prevout.to_str()
        frozen = self._frozen_coins.get(prevout_str, None)
        # frozen is a tri-state, True/False if the user explicitly set it,
        # None otherwise.
        if frozen is not None:  # user has explicitly set the state
            return bool(frozen)
        # State not set. We implicitly mark certain coins as frozen:
        tx_mined_status = self.adb.get_tx_height(utxo.prevout.txid.hex())
        if tx_mined_status.height() == TX_HEIGHT_FUTURE:
            return True
        if self._is_coin_small_and_unconfirmed(utxo):
            return True
        addr = utxo.address
        assert addr is not None
        if self.config.WALLET_FREEZE_REUSED_ADDRESS_UTXOS and self.adb.is_used_as_from_address(addr):
            return True
        return False

    def _is_coin_small_and_unconfirmed(self, utxo: PartialTxInput) -> bool:
        """If true, the coin should not be spent.
        The idea here is that an attacker might send us a UTXO in a
        large low-fee unconfirmed tx that will ~never confirm. If we
        spend it as part of a tx ourselves, that too will not confirm
        (unless we use a high fee, but that might not be worth it for
        a small value UTXO).
        In particular, this test triggers for large "dusting transactions"
        that are used for advertising purposes by some entities.
        see #6960
        """
        # confirmed UTXOs are fine; check this first for performance:
        block_height = utxo.block_height
        assert block_height is not None
        if block_height > 0:
            return False
        # exempt large value UTXOs
        value_sats = utxo.value_sats()
        assert value_sats is not None
        threshold = self.config.WALLET_UNCONF_UTXO_FREEZE_THRESHOLD_SAT
        if value_sats >= threshold:
            return False
        # if funding tx has any is_mine input, then UTXO is fine
        funding_tx = self.db.get_transaction(utxo.prevout.txid.hex())
        if funding_tx is None:
            # we should typically have the funding tx available;
            # might not have it e.g. while not up_to_date
            return True
        if any(self.wallet.is_mine(self.adb.get_txin_address(txin))
               for txin in funding_tx.inputs()):
            return False
        return True

    def filter_frozen(self, coins: Sequence[PartialTxInput]) -> List[PartialTxInput]:
        return [utxo for utxo in coins
                if (not self.is_frozen_address(utxo.address)
                    and not self.is_frozen_coin(utxo))]

    def set_frozen_state_of_addresses(
        self,
        addrs: Iterable[str],
        freeze: bool,
        *,
        write_to_disk: bool = True,
    ) -> bool:
        """Set frozen state of the addresses to FREEZE, True or False"""
        addrs = list(addrs)
        if all(self.wallet.is_mine(addr) for addr in addrs):
            with self.lock:
                if freeze:
                    self._frozen_addresses |= set(addrs)
                else:
                    self._frozen_addresses -= set(addrs)
                self.db.put('frozen_addresses', list(self._frozen_addresses))
            self._notify_frozen_changed(addresses=set(addrs), outpoints=set())
            if write_to_disk:
                self.wallet.save_db()
            return True
        return False

    def set_frozen_state_of_coins(
        self,
        utxos: Iterable[str],
        freeze: Optional[bool],  # tri-state
        *,
        write_to_disk: bool = True,
    ) -> None:
        """Set frozen state of the utxos to `freeze`, True or False (or None).
        A value of True/False means the user explicitly set if the coin should be frozen.
        In contrast, None is the default "unset" state. If unset, is_frozen_coin()
        can decide whether a coin should be frozen.
        """
        utxos = [outpoint_str(utxo) for utxo in utxos]
        # basic sanity check that input is not garbage: (see if raises)
        [TxOutpoint.from_str(utxo) for utxo in utxos]
        assert freeze in (None, False, True), f"{freeze=!r}"
        with self.lock:
            for utxo in utxos:
                if freeze is None:
                    self._frozen_coins.pop(utxo, None)
                else:
                    self._frozen_coins[utxo] = bool(freeze)
        self._notify_frozen_changed(addresses=set(), outpoints=set(utxos))
        if write_to_disk:
            self.wallet.save_db()

    def get_frozen_balance(self) -> tuple[int, int, int]:
        with self.lock:
            frozen_addresses = self._frozen_addresses.copy()
        # note: for coins, use is_frozen_coin instead of _frozen_coins,
        #       as latter only contains *manually* frozen ones
        frozen_coins = {utxo.prevout.to_str() for utxo in self.get_utxos()
                        if self.is_frozen_coin(utxo)}
        if not frozen_coins:  # shortcut
            return self.adb.get_balance(frozen_addresses)
        c1, u1, x1 = self.wallet.get_balance()
        c2, u2, x2 = self.wallet.get_balance(
            excluded_addresses=frozen_addresses,
            excluded_coins=frozen_coins,
        )
        return c1-c2, u1-u2, x1-x2

    def get_frozen_balance_str(self) -> Optional[str]:
        frozen_bal = sum(self.get_frozen_balance())
        if not frozen_bal:
            return None
        return self.config.format_amount_and_units(frozen_bal)

    def is_coin_control_active(self) -> bool:
        with self.lock:
            return bool(self._selection)

    def get_selection(self) -> Set[str]:
        """The raw stored outpoints. Not filtered; for display/introspection."""
        with self.lock:
            return set(self._selection)

    def is_selected(self, coin: CoinType) -> bool:
        with self.lock:
            return outpoint_str(coin) in self._selection

    def _selectable_outpoints(self) -> Set[str]:
        """Coins that may be added to the selection: currently unspent and not
        frozen. Deliberately laxer than get_spendable_coins() -- an unconfirmed
        coin can be selected even while WALLET_SPEND_CONFIRMED_ONLY is set; the
        read-time filter drops it and the status reports num_usable < num_selected.
        """
        return {utxo.prevout.to_str() for utxo in self.filter_frozen(self.get_utxos())}

    def select_coins(self, coins: Iterable[CoinType], *, strict: bool = False) -> Set[str]:
        """Add coins to the selection. Returns the outpoints actually added.

        Silently skips outpoints that are not currently spendable, unless
        `strict`, in which case it raises. (Returning the added set is what lets
        the GUI warn rather than crash; see #10206.)
        """
        wanted = {outpoint_str(c) for c in coins}
        if not wanted:
            return set()
        selectable = self._selectable_outpoints()
        rejected = wanted - selectable
        if rejected and strict:
            raise UserFacingException(
                _("Cannot select coin, it is unknown, already spent or frozen: {}")
                .format(sorted(rejected)[0]))
        with self.lock:
            added = (wanted - rejected) - self._selection
            self._selection |= added
        if added:
            self._notify_coin_control_changed(added=added, removed=set(), reason='user')
        return added

    def deselect_coins(self, coins: Iterable[CoinType]) -> Set[str]:
        wanted = {outpoint_str(c) for c in coins}
        with self.lock:
            removed = wanted & self._selection
            self._selection -= removed
        if removed:
            self._notify_coin_control_changed(added=set(), removed=removed, reason='user')
        return removed

    def set_selection(self, coins: Iterable[CoinType]) -> Set[str]:
        """Replace the selection wholesale."""
        wanted = {outpoint_str(c) for c in coins} & self._selectable_outpoints()
        with self.lock:
            added = wanted - self._selection
            removed = self._selection - wanted
            self._selection = set(wanted)
        if added or removed:
            self._notify_coin_control_changed(added=added, removed=removed, reason='user')
        return added

    def clear_selection(self) -> None:
        with self.lock:
            removed = set(self._selection)
            self._selection.clear()
        if removed:
            self._notify_coin_control_changed(added=set(), removed=removed, reason='cleared')

    def toggle_selection(self, coins: Iterable[CoinType]) -> Set[str]:
        """If coin control is active, turn it off; otherwise select `coins`."""
        if self.is_coin_control_active():
            self.clear_selection()
            return set()
        return self.select_coins(coins)

    def select_addresses(self, addrs: Iterable[str]) -> Set[str]:
        coins = self.get_spendable_coins(list(addrs), ignore_coin_control=True)
        return self.select_coins(coins)

    def deselect_addresses(self, addrs: Iterable[str]) -> Set[str]:
        outpoints = {utxo.prevout.to_str() for utxo in self.get_utxos(list(addrs))}
        return self.deselect_coins(outpoints & self.get_selection())

    def get_coin_control_status(self) -> CoinControlStatus:
        """Everything a frontend needs to render the coin-control indicator."""
        all_utxos = self.get_utxos()
        with self.lock:
            selection = self._selection.copy()
        if not selection:
            return CoinControlStatus(
                is_active=False, num_selected=0, num_usable=0,
                num_total=len(all_utxos), value_sat=0)
        unspent = {utxo.prevout.to_str() for utxo in all_utxos}
        usable = self.get_spendable_coins()
        return CoinControlStatus(
            is_active=True,
            num_selected=len(selection & unspent),
            num_usable=len(usable),
            num_total=len(all_utxos),
            value_sat=sum(utxo.value_sats() for utxo in usable),
        )

    def _discard(self, outpoints: Set[str], *, reason: str) -> None:
        with self.lock:
            removed = outpoints & self._selection
            self._selection -= removed
        if removed:
            self._notify_coin_control_changed(added=set(), removed=removed, reason=reason)

    def _notify_coin_control_changed(self, *, added: Set[str], removed: Set[str], reason: str) -> None:
        self.logger.debug(f'coin control changed ({reason}): +{len(added)} -{len(removed)}')
        util.trigger_callback('coin_control_changed', self.wallet, added, removed, reason)

    def _notify_frozen_changed(self, *, addresses: Set[str], outpoints: Set[str]) -> None:
        util.trigger_callback('frozen_state_changed', self.wallet, addresses, outpoints)

    def _is_our_adb(self, adb) -> bool:
        wallet = self._wallet()
        return wallet is not None and adb == wallet.adb

    @event_listener
    def on_event_adb_added_tx(self, adb, tx_hash: str, tx: 'Transaction'):
        if not self._is_our_adb(adb):
            return
        with self.lock:
            if not self._selection:
                return
            spent = {txin.prevout.to_str() for txin in tx.inputs()} & self._selection
        if spent:
            # drop only the coins that were actually spent, and keep the rest of the selection.
            # clearing everything would silently turn coin control off and let the next send
            # draw from the whole wallet.
            self._discard(spent, reason='spent')

    @event_listener
    def on_event_adb_removed_tx(self, adb, txid: str, tx: Optional['Transaction']):
        if not self._is_our_adb(adb):
            return
        with self.lock:
            if not self._selection:
                return
            # the *funding* tx of a selected coin is gone, so the coin no longer exists
            gone = {op for op in self._selection if op.startswith(txid + ':')}
        if gone:
            self._discard(gone, reason='removed')
