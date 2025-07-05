from typing import Optional, Sequence, Tuple, Union, TYPE_CHECKING, Dict
from decimal import Decimal
from numbers import Real
from enum import IntEnum

from .i18n import _
from .util import NoDynamicFeeEstimates, quantize_feerate, format_fee_satoshis
from . import util, constants
from .logging import Logger

if TYPE_CHECKING:
    from .network import Network

# 1008 = max conf target of core's estimatesmartfee, requesting more results in rpc error.
# estimatesmartfee guarantees that the fee will get accepted into the mempool
FEE_ETA_TARGETS = [1008, 144, 25, 10, 5, 2, 1]
FEE_DEPTH_TARGETS = [10_000_000, 5_000_000, 2_000_000, 1_000_000,
                     800_000, 600_000, 400_000, 250_000, 100_000]
FEERATE_STATIC_VALUES = [1000, 2000, 5000, 10000, 20000, 30000,
                         50000, 70000, 100000, 150000, 200000, 300000]

# satoshi per kbyte
FEERATE_MAX_DYNAMIC = 1500000
FEERATE_WARNING_HIGH_FEE = 600000
FEERATE_FALLBACK_STATIC_FEE = 150000
FEERATE_REGTEST_STATIC_FEE = FEERATE_FALLBACK_STATIC_FEE  # hardcoded fee used on regtest
FEERATE_DEFAULT_RELAY = 1000
FEERATE_MAX_RELAY = 50000

# warn user if fee/amount for on-chain tx is higher than this
FEE_RATIO_HIGH_WARNING = 0.05

# note: make sure the network is asking for estimates for these targets
FEE_LN_ETA_TARGET = 2
FEE_LN_LOW_ETA_TARGET = 25
FEE_LN_MINIMUM_ETA_TARGET = 1008


# The min feerate_per_kw that can be used in lightning so that
# the resulting onchain tx pays the min relay fee.
# This would be FEERATE_DEFAULT_RELAY / 4 if not for rounding errors,
# see https://github.com/ElementsProject/lightning/commit/2e687b9b352c9092b5e8bd4a688916ac50b44af0
FEERATE_PER_KW_MIN_RELAY_LIGHTNING = 253


def closest_index(value, array) -> int:
    dist = list(map(lambda x: abs(x - value), array))
    return min(range(len(dist)), key=dist.__getitem__)


class FeeMethod(IntEnum):
    # note: careful changing these names! they appear in the config files.
    FIXED = 0    # fixed absolute fee
    FEERATE = 1  # fixed fee rate
    ETA = 2      # dynamic, ETA based
    MEMPOOL = 3  # dynamic, mempool based

    @classmethod
    def slider_values(cls):
        return [FeeMethod.FEERATE, FeeMethod.ETA, FeeMethod.MEMPOOL]

    def name_for_GUI(self):
        names = {
            FeeMethod.FEERATE: _('Feerate'),
            FeeMethod.ETA:_('ETA'),
            FeeMethod.MEMPOOL :_('Mempool')
        }
        return names[self]

    @classmethod
    def slider_index_of_method(cls, method):
        try:
            i = FeeMethod.slider_values().index(method)
        except ValueError:
            i = -1
        return i


class FeePolicy(Logger):
    # object associated to a fee slider

    def __init__(self, descriptor: str):
        Logger.__init__(self)
        try:
            name, value = descriptor.split(':')
            self.method = FeeMethod[name.upper()]
            self.value = int(value)  # target (e.g. num blocks, nbytes from mempool tip, sat/kbyte)
        except Exception:
            self.logger.warning(f"Could not parse fee policy descriptor '{descriptor}'. Falling back to 'eta:2'")
            self.method = FeeMethod.ETA
            self.value = 2

    def __repr__(self):
        return self.get_descriptor()

    def get_descriptor(self) -> str:
        return self.method.name.lower() + ':' + str(self.value)

    def set_method(self, method: FeeMethod):
        assert isinstance(method, FeeMethod)
        self.method = method
        # default values
        if self.method == FeeMethod.MEMPOOL:
            self.value = 1000000 # 1 mb from tip
        elif self.method == FeeMethod.ETA:
            self.value = 2 # 2 blocks
        elif self.method == FeeMethod.FEERATE:
            self.value = 5000 # sats per vkb
        else:
            self.value = 10 # sats

    def _get_array(self) -> Sequence[int]:
        if self.method == FeeMethod.MEMPOOL:
            return FEE_DEPTH_TARGETS
        elif self.method == FeeMethod.ETA:
            return FEE_ETA_TARGETS
        elif self.method == FeeMethod.FEERATE:
            return FEERATE_STATIC_VALUES
        else:
            raise Exception('')

    def set_value_from_slider_pos(self, slider_pos: int):
        array = self._get_array()
        slider_pos = max(0, min(slider_pos, len(array)-1))
        self.value = array[slider_pos]

    def get_slider_pos(self) -> int:
        array = self._get_array()
        return closest_index(self.value, array)

    def get_slider_max(self) -> int:
        array = self._get_array()
        maxp = len(array) - 1
        return maxp

    @property
    def use_dynamic_estimates(self):
        return self.method in [FeeMethod.ETA, FeeMethod.MEMPOOL]

    @classmethod
    def depth_target(cls, slider_pos: int) -> int:
        """Returns mempool depth target in bytes for a fee slider position."""
        slider_pos = max(slider_pos, 0)
        slider_pos = min(slider_pos, len(FEE_DEPTH_TARGETS)-1)
        return FEE_DEPTH_TARGETS[slider_pos]

    def eta_target(self, slider_pos: int) -> int:
        """Returns 'num blocks' ETA target for a fee slider position."""
        return FEE_ETA_TARGETS[slider_pos]

    @classmethod
    def eta_tooltip(cls, x):
        if x < 0:
            return _('Low fee')
        elif x == 1:
            return _('In the next block')
        elif x == 144:
            return _('Within one day')
        elif x == 1008:
            return _("Within one week")
        else:
            return _('Within {} blocks').format(x)

    def get_target_text(self):
        """ Description of what the target is: static fee / num blocks to confirm in / mempool depth """
        if self.method == FeeMethod.ETA:
            return self.eta_tooltip(self.value)
        elif self.method == FeeMethod.MEMPOOL:
            return self.depth_tooltip(self.value)
        elif self.method == FeeMethod.FEERATE:
            fee_per_byte = self.value/1000
            return format_fee_satoshis(fee_per_byte) + f" {util.UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE}"

    def get_estimate_text(self, network: 'Network') -> str:
        """
        Description of the current fee estimate corresponding to the target
        """
        fee_per_kb = self.fee_per_kb(network)
        fee_per_byte = fee_per_kb/1000 if fee_per_kb is not None else None
        tooltip = ''
        if self.use_dynamic_estimates:
            if fee_per_byte is not None:
                tooltip = format_fee_satoshis(fee_per_byte) + f" {util.UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE}"
        elif self.method == FeeMethod.FEERATE:
            assert fee_per_kb is not None
            assert fee_per_byte is not None
            if network and network.mempool_fees.has_data():
                depth = network.mempool_fees.fee_to_depth(fee_per_byte)
                tooltip = self.depth_tooltip(depth)
            if network and network.fee_estimates.has_data():
                eta = network.fee_estimates.fee_to_eta(fee_per_kb)
                tooltip += '\n' + self.eta_tooltip(eta)
        return tooltip

    def get_tooltip(self, network: 'Network'):
        target = self.get_target_text()
        estimate = self.get_estimate_text(network)
        if self.use_dynamic_estimates:
            return _('Target') + ': ' + target + '\n' + _('Current rate') + ': ' + estimate
        else:
            return _('Fixed rate') + ': ' + target + '\n' + _('Estimate') + ': ' + estimate

    @classmethod
    def depth_tooltip(cls, depth: Optional[int]) -> str:
        """Returns text tooltip for given mempool depth (in vbytes)."""
        if depth is None:
            return "unknown from tip"
        depth_mb = cls.get_depth_mb_str(depth)
        return _("{} from tip").format(depth_mb)

    @classmethod
    def get_depth_mb_str(cls, depth: int) -> str:
        # e.g. 500_000 -> "0.50 MB"
        depth_mb = "{:.2f}".format(depth / 1_000_000)  # maybe .rstrip("0") ?
        return f"{depth_mb} {util.UI_UNIT_NAME_MEMPOOL_MB}"

    def fee_per_kb(self, network: 'Network') -> Optional[int]:
        """Returns sat/kvB fee to pay for a txn.
        Note: might return None.
        """
        if self.method == FeeMethod.FEERATE:
            fee_rate = self.value
        elif self.method == FeeMethod.MEMPOOL:
            if network:
                fee_rate = network.mempool_fees.depth_to_fee(self.get_slider_pos())
            else:
                fee_rate = None
        elif self.method == FeeMethod.ETA:
            if network:
                fee_rate = network.fee_estimates.eta_to_fee(self.get_slider_pos())
            else:
                fee_rate = None
        else:
            raise Exception(self.method)
        if fee_rate is not None:
            fee_rate = int(fee_rate)
        return fee_rate

    def fee_per_byte(self, network: 'Network') -> Optional[int]:
        """Returns sat/vB fee to pay for a txn.
        Note: might return None.
        """
        fee_per_kb = self.fee_per_kb(network)
        return fee_per_kb / 1000 if fee_per_kb is not None else None

    def estimate_fee(
            self, size: Union[int, float, Decimal], *,
            network: 'Network' = None,
            allow_fallback_to_static_rates: bool = False,
    ) -> int:
        if self.method == FeeMethod.FIXED:
            return self.value
        fee_per_kb = self.fee_per_kb(network)
        if fee_per_kb is None and self.use_dynamic_estimates:
            if allow_fallback_to_static_rates:
                fee_per_kb = FEERATE_FALLBACK_STATIC_FEE
            else:
                raise NoDynamicFeeEstimates()

        return self.estimate_fee_for_feerate(fee_per_kb, size)

    @classmethod
    def estimate_fee_for_feerate(cls, fee_per_kb: Union[int, float, Decimal],
                                 size: Union[int, float, Decimal]) -> int:
        # note: 'size' is in vbytes
        size = Decimal(size)
        fee_per_kb = Decimal(fee_per_kb)
        fee_per_byte = fee_per_kb / 1000
        # to be consistent with what is displayed in the GUI,
        # the calculation needs to use the same precision:
        fee_per_byte = quantize_feerate(fee_per_byte)
        return round(fee_per_byte * size)


class FixedFeePolicy(FeePolicy):
    def __init__(self, fee):
        FeePolicy.__init__(self, 'fixed:%d' % fee)


def impose_hard_limits_on_fee(func):
    def get_fee_within_limits(self, *args, **kwargs):
        fee = func(self, *args, **kwargs)
        if fee is None:
            return fee
        fee = min(FEERATE_MAX_DYNAMIC, fee)
        fee = max(FEERATE_DEFAULT_RELAY, fee)
        return fee
    return get_fee_within_limits


class FeeHistogram:

    def __init__(self):
        self._data = None # type: Optional[Sequence[Tuple[Union[float, int], int]]]

    def has_data(self) -> bool:
        return self._data is not None

    def set_data(self, data):
        self._data = data

    def fee_to_depth(self, target_fee: Real) -> Optional[int]:
        """For a given sat/vbyte fee, returns an estimate of how deep
        it would be in the current mempool in vbytes.
        Pessimistic == overestimates the depth.
        """
        if self._data is None:
            return None
        depth = 0
        for fee, s in self._data:
            depth += s
            if fee <= target_fee:
                break
        return depth

    @impose_hard_limits_on_fee
    def depth_target_to_fee(self, target: int) -> Optional[int]:
        """Returns fee in sat/kbyte.
        target: desired mempool depth in vbytes
        """
        if self._data is None:
            return None
        depth = 0
        for fee, s in self._data:
            depth += s
            if depth > target:
                break
        else:
            return 0
        # add one sat/byte as currently that is the max precision of the histogram
        # note: precision depends on server.
        #       old ElectrumX <1.16 has 1 s/b prec, >=1.16 has 0.1 s/b prec.
        #       electrs seems to use untruncated double-precision floating points.
        #       # TODO decrease this to 0.1 s/b next time we bump the required protocol version
        fee += 1
        # convert to sat/kbyte
        return int(fee * 1000)

    def depth_to_fee(self, slider_pos) -> Optional[int]:
        """Returns fee in sat/kbyte."""
        target = FeePolicy.depth_target(slider_pos)
        return self.depth_target_to_fee(target)

    def get_capped_data(self):
        """ used by QML """
        data = self._data or [[FEERATE_DEFAULT_RELAY/1000,1]]
        # cap the histogram to a limited number of megabytes
        bytes_limit = 10*1000*1000
        bytes_current = 0
        capped_histogram = []
        for item in sorted(data, key=lambda x: x[0], reverse=True):
            if bytes_current >= bytes_limit:
                break
            slot = min(item[1], bytes_limit-bytes_current)
            bytes_current += slot
            capped_histogram.append([
                max(FEERATE_DEFAULT_RELAY/1000, item[0]),  # clamped to [FEERATE_DEFAULT_RELAY/1000,inf[
                slot,  # width of bucket
                bytes_current,  # cumulative depth at far end of bucket
            ])
        return capped_histogram, bytes_current


class FeeTimeEstimates:

    def __init__(self):
        self.data = {} # type: Dict[int, int]

    def get_data(self):
        return self.data

    def has_data(self) -> bool:
        """Returns if we have estimates for *all* targets requested.
        Note: if wanting an estimate for a specific target, instead of checking has_data(),
              just try to do the estimate and handle a potential None result. That way,
              estimation works for targets we have, even if some targets are missing.
        """
        targets = set(FEE_ETA_TARGETS)
        targets.discard(1)  # rm "next block" target
        return all(target in self.data for target in targets)

    def set_data(self, nblock_target: int, fee_per_kb: int):
        assert isinstance(nblock_target, int), f"expected int, got {nblock_target!r}"
        assert isinstance(fee_per_kb, int), f"expected int, got {fee_per_kb!r}"
        self.data[nblock_target] = fee_per_kb

    def fee_to_eta(self, fee_per_kb: Optional[int]) -> int:
        """Returns 'num blocks' ETA estimate for given fee rate,
        or -1 for low fee.
        """
        import operator
        lst = list(self.data.items())
        next_block_fee = self.eta_target_to_fee(1)
        if next_block_fee is not None:
            lst += [(1, next_block_fee)]
        if not lst or fee_per_kb is None:
            return -1
        dist = map(lambda x: (x[0], abs(x[1] - fee_per_kb)), lst)
        min_target, min_value = min(dist, key=operator.itemgetter(1))
        if fee_per_kb < self.data.get(FEE_ETA_TARGETS[0])/2:
            min_target = -1
        return min_target

    def eta_to_fee(self, slider_pos) -> Optional[int]:
        """Returns fee in sat/kbyte."""
        slider_pos = max(slider_pos, 0)
        slider_pos = min(slider_pos, len(FEE_ETA_TARGETS) - 1)
        if slider_pos < len(FEE_ETA_TARGETS) - 1:
            num_blocks = FEE_ETA_TARGETS[int(slider_pos)]
            fee = self.eta_target_to_fee(num_blocks)
        else:
            fee = self.eta_target_to_fee(1)
        return fee

    @impose_hard_limits_on_fee
    def eta_target_to_fee(self, num_blocks: int) -> Optional[int]:
        """Returns fee in sat/kbyte."""
        if num_blocks == 1:
            fee = self.data.get(2)
            if fee is not None:
                fee += fee / 2
                fee = int(fee)
        else:
            fee = self.data.get(num_blocks)
            if fee is not None:
                fee = int(fee)
        # fallback for regtest
        if fee is None and constants.net is constants.BitcoinRegtest:
            return FEERATE_REGTEST_STATIC_FEE
        return fee
