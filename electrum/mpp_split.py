import random
import math
from typing import List, Tuple, Dict, NamedTuple

from .lnutil import NoPathFound

PART_PENALTY = 1.0  # 1.0 results in avoiding splits
MIN_PART_SIZE_MSAT = 10_000_000  # we don't want to split indefinitely
EXHAUST_DECAY_FRACTION = 10  # fraction of the local balance that should be reserved if possible
RELATIVE_SPLIT_SPREAD = 0.3  # deviation from the mean when splitting amounts into parts

# these parameters affect the computational work in the probabilistic algorithm
CANDIDATES_PER_LEVEL = 20
MAX_PARTS = 5  # maximum number of parts for splitting


# maps a channel (channel_id, node_id) to the funds it has available
ChannelsFundsInfo = Dict[Tuple[bytes, bytes], Tuple[int, int]]


class SplitConfig(dict, Dict[Tuple[bytes, bytes], List[int]]):
    """maps a channel (channel_id, node_id) to a list of amounts"""
    def number_parts(self) -> int:
        return sum([len(v) for v in self.values() if sum(v)])

    def number_nonzero_channels(self) -> int:
        return len([v for v in self.values() if sum(v)])

    def number_nonzero_nodes(self) -> int:
        # using a set comprehension
        return len({nodeid for (_, nodeid), amounts in self.items() if sum(amounts)})

    def total_config_amount(self) -> int:
        return sum([sum(c) for c in self.values()])

    def is_any_amount_smaller_than_min_part_size(self) -> bool:
        smaller = False
        for amounts in self.values():
            if any([amount < MIN_PART_SIZE_MSAT for amount in amounts]):
                smaller |= True
        return smaller


class SplitConfigRating(NamedTuple):
    config: SplitConfig
    rating: float


def split_amount_normal(total_amount: int, num_parts: int) -> List[int]:
    """Splits an amount into about `num_parts` parts, where the parts are split
    randomly (normally distributed around amount/num_parts with certain spread)."""
    parts = []
    avg_amount = total_amount / num_parts
    # roughly reach total_amount
    while total_amount - sum(parts) > avg_amount:
        amount_to_add = int(abs(random.gauss(avg_amount, RELATIVE_SPLIT_SPREAD * avg_amount)))
        if sum(parts) + amount_to_add < total_amount:
            parts.append(amount_to_add)
    # add what's missing
    parts.append(total_amount - sum(parts))
    return parts


def remove_duplicates(configs: List[SplitConfig]) -> List[SplitConfig]:
    unique_configs = set()
    for config in configs:
        # sort keys and values
        config_sorted_values = {k: sorted(v) for k, v in config.items()}
        config_sorted_keys = {k: config_sorted_values[k] for k in sorted(config_sorted_values.keys())}
        hashable_config = tuple((c, tuple(sorted(config[c]))) for c in config_sorted_keys)
        unique_configs.add(hashable_config)
    unique_configs = [SplitConfig({c[0]: list(c[1]) for c in config}) for config in unique_configs]
    return unique_configs


def remove_multiple_nodes(configs: List[SplitConfig]) -> List[SplitConfig]:
    return [config for config in configs if config.number_nonzero_nodes() == 1]


def remove_single_part_configs(configs: List[SplitConfig]) -> List[SplitConfig]:
    return [config for config in configs if config.number_parts() != 1]


def remove_single_channel_splits(configs: List[SplitConfig]) -> List[SplitConfig]:
    return [
        config for config in configs
        if all(len(channel_splits) <= 1 for channel_splits in config.values())
    ]

def rate_config(
        config: SplitConfig,
        channels_with_funds: ChannelsFundsInfo) -> float:
    """Defines an objective function to rate a configuration.

    We calculate the normalized L2 norm for a configuration and
    add a part penalty for each nonzero amount. The consequence is that
    amounts that are equally distributed and have less parts are rated
    lowest (best). A penalty depending on the total amount sent over a channel
    counteracts channel exhaustion."""
    rating = 0
    total_amount = config.total_config_amount()

    for channel, amounts in config.items():
        funds, slots = channels_with_funds[channel]
        if amounts:
            for amount in amounts:
                rating += amount * amount / (total_amount * total_amount)  # penalty to favor equal distribution of amounts
                rating += PART_PENALTY * PART_PENALTY  # penalty for each part
            decay = funds / EXHAUST_DECAY_FRACTION
            rating += math.exp((sum(amounts) - funds) / decay)  # penalty for channel exhaustion
    return rating


def suggest_splits(
        amount_msat: int,
        channels_with_funds: ChannelsFundsInfo,
        exclude_single_part_payments=False,
        exclude_multinode_payments=False,
        exclude_single_channel_splits=False
) -> List[SplitConfigRating]:
    """Breaks amount_msat into smaller pieces and distributes them over the
    channels according to the funds they can send.

    Individual channels may be assigned multiple parts. The split configurations
    are returned in sorted order, from best to worst rating.

    Single part payments can be excluded, since they represent legacy payments.
    Split configurations that send via multiple nodes can be excluded as well.
    """

    configs = []
    channel_keys = list(channels_with_funds.keys())

    # generate multiple configurations to get more configurations (there is randomness in this loop)
    for _ in range(CANDIDATES_PER_LEVEL):
        # we want to have configurations with no splitting to many splittings
        for target_parts in range(1, MAX_PARTS):
            config = SplitConfig()
            # randomly split amount into target_parts chunks
            split_amounts = split_amount_normal(amount_msat, target_parts)
            # randomly distribute amounts over channels
            for amount in split_amounts:
                random.shuffle(channel_keys)
                # we check each channel and try to put the funds inside, break if we succeed
                for c in channel_keys:
                    if c not in config:
                        config[c] = []
                    channel_funds, channel_slots = channels_with_funds[c]
                    if sum(config[c]) + amount <= channel_funds and len(config[c]) < channel_slots:
                        config[c].append(amount)
                        break
                # if we don't succeed to put the amount anywhere,
                # we try to fill up channels and put the rest somewhere else
                else:
                    distribute_amount = amount
                    for c in channel_keys:
                        channel_funds, channel_slots = channels_with_funds[c]
                        slots_left = channel_slots - len(config[c])
                        if slots_left == 0:
                            # no slot left in that channel
                            continue
                        funds_left = channel_funds - sum(config[c])
                        # it would be good to not fill the full channel if possible
                        add_amount = min(funds_left, distribute_amount)
                        config[c].append(add_amount)
                        distribute_amount -= add_amount
                        if distribute_amount == 0:
                            break
            if config.total_config_amount() != amount_msat:
                continue
            if target_parts > 1 and config.is_any_amount_smaller_than_min_part_size():
                if target_parts == 2:
                    # if there are already too small parts at the first split excluding single
                    # part payments may return only few configurations, this will allow single part
                    # payments for more payments, if they are too small to split
                    exclude_single_part_payments = False
                continue
            assert config.total_config_amount() == amount_msat
            configs.append(config)
        if not configs:
            raise NoPathFound('Cannot distribute payment over channels.')

    configs = remove_duplicates(configs)

    # we only take configurations that send via a single node (but there can be multiple parts)
    if exclude_multinode_payments:
        configs = remove_multiple_nodes(configs)

    if exclude_single_part_payments:
        configs = remove_single_part_configs(configs)

    if exclude_single_channel_splits:
        configs = remove_single_channel_splits(configs)

    rated_configs = [SplitConfigRating(
        config=c,
        rating=rate_config(c, channels_with_funds)
    ) for c in configs]
    rated_configs.sort(key=lambda x: x.rating)

    return rated_configs
