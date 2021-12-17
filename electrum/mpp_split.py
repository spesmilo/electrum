import random
import math
from typing import List, Tuple, Dict, NamedTuple
from collections import defaultdict

from .lnutil import NoPathFound

PART_PENALTY = 1.0  # 1.0 results in avoiding splits
MIN_PART_SIZE_MSAT = 10_000_000  # we don't want to split indefinitely
EXHAUST_DECAY_FRACTION = 10  # fraction of the local balance that should be reserved if possible
RELATIVE_SPLIT_SPREAD = 0.3  # deviation from the mean when splitting amounts into parts

# these parameters affect the computational work in the probabilistic algorithm
CANDIDATES_PER_LEVEL = 20
MAX_PARTS = 5  # maximum number of parts for splitting


# maps a channel (channel_id, node_id) to a list of amounts
SplitConfig = Dict[Tuple[bytes, bytes], List[int]]
# maps a channel (channel_id, node_id) to the funds it has available
ChannelsFundsInfo = Dict[Tuple[bytes, bytes], int]


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


def number_parts(config: SplitConfig) -> int:
    return sum([len(v) for v in config.values() if sum(v)])


def number_nonzero_channels(config: SplitConfig) -> int:
    return len([v for v in config.values() if sum(v)])


def number_nonzero_nodes(config: SplitConfig) -> int:
    # using a set comprehension
    return len({nodeid for (_, nodeid), amounts in config.items() if sum(amounts)})


def total_config_amount(config: SplitConfig) -> int:
    return sum([sum(c) for c in config.values()])


def is_any_amount_smaller_than_min_part_size(config: SplitConfig) -> bool:
    smaller = False
    for amounts in config.values():
        if any([amount < MIN_PART_SIZE_MSAT for amount in amounts]):
            smaller |= True
    return smaller


def remove_duplicates(configs: List[SplitConfig]) -> List[SplitConfig]:
    unique_configs = set()
    for config in configs:
        # sort keys and values
        config_sorted_values = {k: sorted(v) for k, v in config.items()}
        config_sorted_keys = {k: config_sorted_values[k] for k in sorted(config_sorted_values.keys())}
        hashable_config = tuple((c, tuple(sorted(config[c]))) for c in config_sorted_keys)
        unique_configs.add(hashable_config)
    unique_configs = [{c[0]: list(c[1]) for c in config} for config in unique_configs]
    return unique_configs


def remove_multiple_nodes(configs: List[SplitConfig]) -> List[SplitConfig]:
    return [config for config in configs if number_nonzero_nodes(config) == 1]


def remove_single_part_configs(configs: List[SplitConfig]) -> List[SplitConfig]:
    return [config for config in configs if number_parts(config) != 1]


def remove_single_channel_splits(configs: List[SplitConfig]) -> List[SplitConfig]:
    filtered = []
    for config in configs:
        for v in config.values():
            if len(v) > 1:
                continue
            filtered.append(config)
    return filtered


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
    total_amount = total_config_amount(config)

    for channel, amounts in config.items():
        funds = channels_with_funds[channel]
        if amounts:
            for amount in amounts:
                rating += amount * amount / (total_amount * total_amount)  # penalty to favor equal distribution of amounts
                rating += PART_PENALTY * PART_PENALTY  # penalty for each part
            decay = funds / EXHAUST_DECAY_FRACTION
            rating += math.exp((sum(amounts) - funds) / decay)  # penalty for channel exhaustion
    return rating


def suggest_splits(
        amount_msat: int, channels_with_funds: ChannelsFundsInfo,
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
    channels_order = list(channels_with_funds.keys())

    # generate multiple configurations to get more configurations (there is randomness in this loop)
    for _ in range(CANDIDATES_PER_LEVEL):
        # we want to have configurations with no splitting to many splittings
        for target_parts in range(1, MAX_PARTS):
            config = defaultdict(list)  # type: SplitConfig

            # randomly split amount into target_parts chunks
            split_amounts = split_amount_normal(amount_msat, target_parts)
            # randomly distribute amounts over channels
            for amount in split_amounts:
                random.shuffle(channels_order)
                # we check each channel and try to put the funds inside, break if we succeed
                for c in channels_order:
                    if sum(config[c]) + amount <= channels_with_funds[c]:
                        config[c].append(amount)
                        break
                # if we don't succeed to put the amount anywhere,
                # we try to fill up channels and put the rest somewhere else
                else:
                    distribute_amount = amount
                    for c in channels_order:
                        funds_left = channels_with_funds[c] - sum(config[c])
                        # it would be good to not fill the full channel if possible
                        add_amount = min(funds_left, distribute_amount)
                        config[c].append(add_amount)
                        distribute_amount -= add_amount
                        if distribute_amount == 0:
                            break
            if total_config_amount(config) != amount_msat:
                raise NoPathFound('Cannot distribute payment over channels.')
            if target_parts > 1 and is_any_amount_smaller_than_min_part_size(config):
                continue
            assert total_config_amount(config) == amount_msat
            configs.append(config)

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
