import binascii
import pprint
import sys

from hmac_drbg import *

def parse_entry(line):
    key, val = line.split('=')
    key = key.strip()
    val = val.strip()
    if val == 'True':
        val = True
    elif val == 'False':
        val = False
    elif val.isdigit():
        val = int(val)
    return key, val

def parse_rsp(rsp_file):
    test_suites = []
    suite = {}
    test = {}

    with open(rsp_file, 'r') as f:
        while True:
            line = f.readline()
            if line == '':
                break

            if line == '\n' or line == '\r\n':
                continue

            if line.startswith('#'):
                continue

            line = line.strip()

            if line.startswith('['):
                e = line[1:-1]
                if not '=' in e:
                    if suite:
                        test_suites.append(suite)
                    suite = {'Algorithm': e, 'Tests': []}
                    test = {}
                else:
                    key, val = parse_entry(e)
                    suite[key] = val
                continue

            if line.startswith('COUNT'):
                if test:
                    suite['Tests'].append(test)
                test = {}
                continue

            key, val = parse_entry(line)
            if key in test:
                key = key + '2'
            test[key] = val

    return test_suites

# generate test cases for go-drbg
def dump_go(tests):
    pr_fields = ['EntropyInput', 'Nonce', 'PersonalizationString', 'AdditionalInput', 'EntropyInputPR', 'AdditionalInput2', 'EntropyInputPR2', 'ReturnedBits']

    print('package hmac\n')
    print('var HmacSha512PrTests = []map[string]string{')
    for t in tests:
        print('\t{')
        for k in pr_fields:
            print('\t\t"{}": "{}",'.format(k, t[k]))
        print('\t},')
    print('}')

def run_tests(tests):
    for test in tests:
        t = {k: binascii.unhexlify(v) for k, v in test.items()}
        l = len(t['ReturnedBits'])
        print(t['EntropyInput'] + t['Nonce'] + t['PersonalizationString'])
        drbg = DRBG(t['EntropyInput'] + t['Nonce'] + t['PersonalizationString'])
        drbg.reseed(t['EntropyInputPR'] + t['AdditionalInput'])
        drbg.generate(l)

        drbg.reseed(t['EntropyInputPR2'] + t['AdditionalInput2'])
        result = drbg.generate(l)

        if result != t['ReturnedBits']:
            print('FAILED TEST:')
            pprint.pprint(test)
            print('\nGot:', binascii.hexlify(result).decode('ascii'))
            return

    print('Passed all %s tests.' % len(tests))

def main():
    test_suites = parse_rsp('HMAC_DRBG_PR.rsp')

    # NOTE customize this code
    tests = []
    for t in test_suites:
        if t['Algorithm'] == 'SHA-512':
            tests += t['Tests']

    run_tests(tests)


if __name__ == '__main__':
    main()
