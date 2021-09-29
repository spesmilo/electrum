import random
import math
from typing import List, Tuple, Optional, Sequence, Dict, TYPE_CHECKING
from collections import defaultdict

from .util import profiler
from .lnutil import NoPathFound

PART_PENALTY = 1.0  # 1.0 results in avoiding splits
MIN_PART_MSAT = 10_000_000  # we don't want to split indefinitely
EXHAUST_DECAY_FRACTION = 10  # fraction of the local balance that should be reserved if possible

# these parameters determine the granularity of the newly suggested configurations
REDISTRIBUTION_FRACTION = 50
SPLIT_FRACTION = 50

# these parameters affect the computational work in the probabilistic algorithm
STARTING_CONFIGS = 50
CANDIDATES_PER_LEVEL = 10
REDISTRIBUTE = 20

# maximum number of parts for splitting
MAX_PARTS = 5


def unique_hierarchy(hierarchy: Dict[int, List[Dict[Tuple[bytes, bytes], int]]]) -> Dict[int, List[Dict[Tuple[bytes, bytes], int]]]:
    new_hierarchy = defaultdict(list)
    for number_parts, configs in hierarchy.items():
        unique_configs = set()
        for config in configs:
            # config dict can be out of order, so sort, otherwise not unique
            unique_configs.add(tuple((c, config[c]) for c in sorted(config.keys())))
        for unique_config in sorted(unique_configs):
            new_hierarchy[number_parts].append(
                {t[0]: t[1] for t in unique_config})
    return new_hierarchy


def single_node_hierarchy(hierarchy: Dict[int, List[Dict[Tuple[bytes, bytes], int]]]) -> Dict[int, List[Dict[Tuple[bytes, bytes], int]]]:
    new_hierarchy = defaultdict(list)
    for number_parts, configs in hierarchy.items():
        for config in configs:
            # determine number of nodes in configuration
            if number_nonzero_nodes(config) > 1:
                continue
            new_hierarchy[number_parts].append(config)
    return new_hierarchy


def number_nonzero_parts(configuration: Dict[Tuple[bytes, bytes], int]) -> int:
    return len([v for v in configuration.values() if v])


def number_nonzero_nodes(configuration: Dict[Tuple[bytes, bytes], int]) -> int:
    return len({nodeid for (_, nodeid), amount in configuration.items() if amount > 0})


def create_starting_split_hierarchy(amount_msat: int, channels_with_funds: Dict[Tuple[bytes, bytes], int]):
    """Distributes the amount to send to a single or more channels in several
    ways (randomly)."""
    # TODO: find all possible starting configurations deterministically
    # could try all permutations

    split_hierarchy = defaultdict(list)
    channels_order = list(channels_with_funds.keys())

    for _ in range(STARTING_CONFIGS):
        # shuffle to have different starting points
        random.shuffle(channels_order)

        configuration = {}
        amount_added = 0
        for c in channels_order:
            s = channels_with_funds[c]
            if amount_added == amount_msat:
                configuration[c] = 0
            else:
                amount_to_add = amount_msat - amount_added
                amt = min(s, amount_to_add)
                configuration[c] = amt
                amount_added += amt
        if amount_added != amount_msat:
            raise NoPathFound("Channels don't have enough sending capacity.")
        split_hierarchy[number_nonzero_parts(configuration)].append(configuration)

    return unique_hierarchy(split_hierarchy)


def balances_are_not_ok(proposed_balance_from, channel_from, proposed_balance_to, channel_to, channels_with_funds):
    check = (
            proposed_balance_to < MIN_PART_MSAT or
            proposed_balance_to > channels_with_funds[channel_to] or
            proposed_balance_from < MIN_PART_MSAT or
            proposed_balance_from > channels_with_funds[channel_from]
    )
    return check


def propose_new_configuration(channels_with_funds: Dict[Tuple[bytes, bytes], int], configuration: Dict[Tuple[bytes, bytes], int],
                              amount_msat: int, preserve_number_parts=True) -> Dict[Tuple[bytes, bytes], int]:
    """Randomly alters a split configuration. If preserve_number_parts, the
    configuration stays within the same class of number of splits."""

    # there are three basic operations to reach different split configurations:
    # redistribute, split, swap

    def redistribute(config: dict):
        # we redistribute the amount from a nonzero channel to a nonzero channel
        redistribution_amount = amount_msat // REDISTRIBUTION_FRACTION
        nonzero = [ck for ck, cv in config.items() if
                   cv >= redistribution_amount]
        if len(nonzero) == 1:  # we only have a single channel, so we can't redistribute
            return config

        channel_from = random.choice(nonzero)
        channel_to = random.choice(nonzero)
        if channel_from == channel_to:
            return config
        proposed_balance_from = config[channel_from] - redistribution_amount
        proposed_balance_to = config[channel_to] + redistribution_amount
        if balances_are_not_ok(proposed_balance_from, channel_from, proposed_balance_to, channel_to, channels_with_funds):
            return config
        else:
            config[channel_from] = proposed_balance_from
            config[channel_to] = proposed_balance_to
        assert sum([cv for cv in config.values()]) == amount_msat
        return config

    def split(config: dict):
        # we split off a certain amount from a nonzero channel and put it into a
        # zero channel
        nonzero = [ck for ck, cv in config.items() if cv != 0]
        zero = [ck for ck, cv in config.items() if cv == 0]
        try:
            channel_from = random.choice(nonzero)
            channel_to = random.choice(zero)
        except IndexError:
            return config
        delta = config[channel_from] // SPLIT_FRACTION
        proposed_balance_from = config[channel_from] - delta
        proposed_balance_to = config[channel_to] + delta
        if balances_are_not_ok(proposed_balance_from, channel_from, proposed_balance_to, channel_to, channels_with_funds):
            return config
        else:
            config[channel_from] = proposed_balance_from
            config[channel_to] = proposed_balance_to
            assert sum([cv for cv in config.values()]) == amount_msat
        return config

    def swap(config: dict):
        # we swap the amounts from a single channel with another channel
        nonzero = [ck for ck, cv in config.items() if cv != 0]
        all = list(config.keys())

        channel_from = random.choice(nonzero)
        channel_to = random.choice(all)

        proposed_balance_to = config[channel_from]
        proposed_balance_from = config[channel_to]
        if balances_are_not_ok(proposed_balance_from, channel_from, proposed_balance_to, channel_to, channels_with_funds):
            return config
        else:
            config[channel_to] = proposed_balance_to
            config[channel_from] = proposed_balance_from
        return config

    initial_number_parts = number_nonzero_parts(configuration)

    for _ in range(REDISTRIBUTE):
        configuration = redistribute(configuration)
    if not preserve_number_parts and number_nonzero_parts(
            configuration) == initial_number_parts:
        configuration = split(configuration)
    configuration = swap(configuration)

    return configuration


@profiler
def suggest_splits(amount_msat: int, channels_with_funds: Dict[Tuple[bytes, bytes], int],
                   exclude_single_parts=True, single_node=False) \
        -> Sequence[Tuple[Dict[Tuple[bytes, bytes], int], float]]:
    """Creates split configurations for a payment over channels. Single channel
    payments are excluded by default. channels_with_funds is keyed by
    (channelid, nodeid)."""

    def rate_configuration(config: dict) -> float:
        """Defines an objective function to rate a split configuration.

        We calculate the normalized L2 norm for a split configuration and
        add a part penalty for each nonzero amount. The consequence is that
        amounts that are equally distributed and have less parts are rated
        lowest."""
        F = 0
        total_amount = sum([v for v in config.values()])

        for channel, amount in config.items():
            funds = channels_with_funds[channel]
            if amount:
                F += amount * amount / (total_amount * total_amount)  # a penalty to favor distribution of amounts
                F += PART_PENALTY * PART_PENALTY  # a penalty for each part
                decay = funds / EXHAUST_DECAY_FRACTION
                F += math.exp((amount - funds) / decay)  # a penalty for channel saturation

        return F

    def rated_sorted_configurations(hierarchy: dict) -> Sequence[Tuple[Dict[Tuple[bytes, bytes], int], float]]:
        """Cleans up duplicate splittings, rates and sorts them according to
        the rating. A lower rating is a better configuration."""
        hierarchy = unique_hierarchy(hierarchy)
        rated_configs = []
        for level, configs in hierarchy.items():
            for config in configs:
                rated_configs.append((config, rate_configuration(config)))
        sorted_rated_configs = sorted(rated_configs, key=lambda c: c[1], reverse=False)
        return sorted_rated_configs

    # create initial guesses
    split_hierarchy = create_starting_split_hierarchy(amount_msat, channels_with_funds)

    # randomize initial guesses and generate splittings of different split
    # levels up to number of channels
    for level in range(2, min(MAX_PARTS, len(channels_with_funds) + 1)):
        # generate a set of random configurations for each level
        for _ in range(CANDIDATES_PER_LEVEL):
            configurations = unique_hierarchy(split_hierarchy).get(level, None)
            if configurations:  # we have a splitting of the desired number of parts
                configuration = random.choice(configurations)
                # generate new splittings preserving the number of parts
                configuration = propose_new_configuration(
                    channels_with_funds, configuration, amount_msat,
                    preserve_number_parts=True)
            else:
                # go one level lower and look for valid splittings,
                # try to go one level higher by splitting a single outgoing amount
                configurations = unique_hierarchy(split_hierarchy).get(level - 1, None)
                if not configurations:
                    continue
                configuration = random.choice(configurations)
                # generate new splittings going one level higher in the number of parts
                configuration = propose_new_configuration(
                    channels_with_funds, configuration, amount_msat,
                    preserve_number_parts=False)

            # add the newly found configuration (doesn't matter if nothing changed)
            split_hierarchy[number_nonzero_parts(configuration)].append(configuration)

    if exclude_single_parts:
        # we only want to return configurations that have at least two parts
        try:
            del split_hierarchy[1]
        except:
            pass

    if single_node:
        # we only take configurations that send to a single node
        split_hierarchy = single_node_hierarchy(split_hierarchy)

    return rated_sorted_configurations(split_hierarchy)
