from typing import Optional, Sequence, Tuple, Union, TYPE_CHECKING
from decimal import Decimal
from numbers import Real
from enum import IntEnum

from .i18n import _
from .util import NoDynamicFeeEstimates, quantize_feerate, format_fee_satoshis
from . import util
from . import constants

if TYPE_CHECKING:
    from .network import Network

FEE_ETA_TARGETS = [25, 10, 5, 2, 1]
FEE_DEPTH_TARGETS = [10_000_000, 5_000_000, 2_000_000, 1_000_000,
                     800_000, 600_000, 400_000, 250_000, 100_000]
FEERATE_STATIC_VALUES = [1000, 2000, 5000, 10000, 20000, 30000,
                         50000, 70000, 100000, 150000, 200000, 300000]

# satoshi per kbyte
FEERATE_MAX_DYNAMIC = 1500000
FEERATE_WARNING_HIGH_FEE = 600000
FEERATE_FALLBACK_STATIC_FEE = 150000
FEERATE_DEFAULT_RELAY = 1000
FEERATE_MAX_RELAY = 50000

# warn user if fee/amount for on-chain tx is higher than this
FEE_RATIO_HIGH_WARNING = 0.05


def closest_index(value, array) -> int:
    dist = list(map(lambda x: abs(x - value), array))
    return min(range(len(dist)), key=dist.__getitem__)


class FeeMethod(IntEnum):
    CONSTANT = 0
    STATIC = 1
    ETA = 2
    MEMPOOL = 3


class FeePolicy:
    # object associated to a fee slider

    def __init__(self, descriptor: str):
        try:
            name, value = descriptor.split(':')
            self.method = FeeMethod[name.upper()]
            self.value = int(value)
        except Exception:
            # default values
            self.method = FeeMethod.ETA
            self.value = 2

    def get_descriptor(self) -> str:
        return self.method.name.lower() + ':' + str(self.value)

    def set_method(self, method: FeeMethod):
        assert isinstance(method, FeeMethod)
        self.method = method
        self.value = 0

    def _get_array(self) -> Sequence[int]:
        if self.method == FeeMethod.MEMPOOL:
            return FEE_DEPTH_TARGETS
        elif self.method == FeeMethod.ETA:
            return FEE_ETA_TARGETS
        elif self.method == FeeMethod.STATIC:
            return FEERATE_STATIC_VALUES
        else:
            raise Exception('')

    def set_value_from_slider_pos(self, slider_pos: int):
        array = self._get_array()
        slider_pos = max(0, min(slider_pos, len(array)-1))
        self.value = array[slider_pos]

    @property
    def slider_pos(self) -> int:
        array = self._get_array()
        return closest_index(self.value, array)

    def get_slider_max(self) -> int:
        array = self._get_array()
        maxp = len(array) - 1
        return maxp

    def get_slider(self) -> Tuple[int, int]:
        return self.get_slider_max(), self.slider_pos

    @property
    def use_dynamic_estimates(self):
        return self.method in [FeeMethod.ETA, FeeMethod.MEMPOOL]

    @classmethod
    def depth_target(self, slider_pos: int) -> int:
        """Returns mempool depth target in bytes for a fee slider position."""
        slider_pos = max(slider_pos, 0)
        slider_pos = min(slider_pos, len(FEE_DEPTH_TARGETS)-1)
        return FEE_DEPTH_TARGETS[slider_pos]

    def eta_target(self, slider_pos: int) -> int:
        """Returns 'num blocks' ETA target for a fee slider position."""
        return FEE_ETA_TARGETS[slider_pos]

    @classmethod
    def eta_tooltip(self, x):
        if x < 0:
            return _('Low fee')
        elif x == 1:
            return _('In the next block')
        else:
            return _('Within {} blocks').format(x)

    def get_target_text(self):
        """ Description of what the target is: static fee / num blocks to confirm in / mempool depth """
        if self.method == FeeMethod.ETA:
            return self.eta_tooltip(self.value)
        elif self.method == FeeMethod.MEMPOOL:
            return self.depth_tooltip(self.value)
        elif self.method == FeeMethod.STATIC:
            fee_per_byte = self.value/1000
            return format_fee_satoshis(fee_per_byte) + f" {util.UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE}"

    def get_estimate_text(self, network: 'Network'):
        """
        Description of the current fee estimate corresponding to the target
        """
        fee_per_kb = self.fee_per_kb(network)
        if fee_per_kb is None:
            rate_str = 'unknown'
            fee_per_byte = None
        else:
            fee_per_byte = fee_per_kb/1000
            rate_str = format_fee_satoshis(fee_per_byte) + f" {util.UI_UNIT_NAME_FEERATE_SAT_PER_VBYTE}"

        if self.use_dynamic_estimates:
            tooltip = rate_str

        elif self.method == FeeMethod.STATIC:
            assert fee_per_kb is not None
            assert fee_per_byte is not None
            if network.mempool_fees.has_data():
                depth = network.mempool_fees.fee_to_depth(fee_per_byte)
                tooltip = self.depth_tooltip(depth)
            else:
                tooltip = ''
            if network.fee_estimates.has_data():
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
    def depth_tooltip(self, depth: Optional[int]) -> str:
        """Returns text tooltip for given mempool depth (in vbytes)."""
        if depth is None:
            return "unknown from tip"
        depth_mb = self.get_depth_mb_str(depth)
        return _("{} from tip").format(depth_mb)

    @classmethod
    def get_depth_mb_str(self, depth: int) -> str:
        # e.g. 500_000 -> "0.50 MB"
        depth_mb = "{:.2f}".format(depth / 1_000_000)  # maybe .rstrip("0") ?
        return f"{depth_mb} {util.UI_UNIT_NAME_MEMPOOL_MB}"

    def fee_per_kb(self, network: 'Network') -> Optional[int]:
        """Returns sat/kvB fee to pay for a txn.
        Note: might return None.
        fee_level: float between 0.0 and 1.0, representing fee slider position
        """
        if constants.net is constants.BitcoinRegtest:
            return FEERATE_STATIC_VALUES[self.slider_pos]
        # there is no fee_level specified; will use config.
        # note: 'depth_level' and 'fee_level' in config are integer slider positions,
        # unlike fee_level here, which (when given) is a float in [0.0, 1.0]
        if self.method == FeeMethod.MEMPOOL:
            fee_rate = network.mempool_fees.depth_to_fee(self.slider_pos)
        elif self.method == FeeMethod.ETA:
            fee_rate = network.fee_estimates.eta_to_fee(self.slider_pos)
        elif self.method == FeeMethod.STATIC:
            fee_rate = self.value
        else:
            raise Exception(self.method)
        if fee_rate is not None:
            fee_rate = int(fee_rate)
        return fee_rate

    def fee_per_byte(self, network: 'Network'):
        """Returns sat/vB fee to pay for a txn.
        Note: might return None.
        """
        fee_per_kb = self.fee_per_kb(network)
        return fee_per_kb / 1000 if fee_per_kb is not None else None

    def estimate_fee(self, network: 'Network', size: Union[int, float, Decimal], *,
                     allow_fallback_to_static_rates: bool = False) -> int:
        if self.method == FeeMethod.CONSTANT:
            return self.value
        if network is None and self.use_dynamic_estimates:
            if allow_fallback_to_static_rates:
                fee_per_kb = FEERATE_FALLBACK_STATIC_FEE
            else:
                raise NoDynamicFeeEstimates()
        else:
            fee_per_kb = self.fee_per_kb(network)

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


def impose_hard_limits_on_fee(func):
    def get_fee_within_limits(self, *args, **kwargs):
        fee = func(self, *args, **kwargs)
        if fee is None:
            return fee
        fee = min(FEERATE_MAX_DYNAMIC, fee)
        fee = max(FEERATE_DEFAULT_RELAY, fee)
        return fee
    return get_fee_within_limits


class FeeHistogram(list):

    def __init__(self):
        self._data = None

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


class FeeTimeEstimates:

    def __init__(self):
        self.data = {}

    def has_data(self):
        return len(self.data) == 4

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
        return fee
