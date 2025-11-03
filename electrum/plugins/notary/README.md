The notary API has 3 public endpoints


notarize
========

Notarize takes a hash (nostr event_id) and a value (to be burnt).

```bash
curl -X POST http://localhost:5455/api/notarize -H 'Content-Type: application/json' -d '{ "event_id":"277419e0a32a8e2181f5b29102eb5008c53fec1b6d980d4b33d0a0aaadf44fc2", "value":128 }' 
```

This returns a lightning invoice and a rhash:

```json
{
  "invoice": "lnbcrt80n1p507j4zpp5lyae3cm5v3w7nkxwu4vcx32dqr49g485prqrvk8vh764nxrajatqsp5p53uxxxwgwkuganeraeepkmvykfwqpthnavjndsuflcxf3u58jasdr8xuerjcejxvekxdpcvdnxgwfc8yenwwphv5ukzvfkvcmrzvtzvgmnsv348ycrvctpxgcnwerrx56nvctrv4jx2df4x5crjwt9v9skydqcqzynxqrrss9qlzqqqqqqqqqqqqqqqqqqqqqqqqqqysgqrzjq2xevues3u96zjnms0x9a69sf3lmxf0su6f6uyvfjt90p6gwfk4a6paec4eks2wj4vqqqqqqqqqqqqqqqyw3hkzdvce5afyud02k8l6ezvqmrk3sjmrlsz0ynrzwxf770qqpqheu9zjf64lzzdj25r8kx9nsvnnhyqew8v7qmgweu6l8tcc8h7yzgqdaexks",
  "rhash": "a5d29d8ee774353204b1aa164e23d5012187ebf5f2594f2698417ae2deeada5b"
}
```

The notary will add a notarization fee to the initial value.
The invoice amount is the sum of both.
The public proof will be available after the invoice has been paid.


get_proof
=========

```bash
curl -X POST http://localhost:5455/api/get_proof -H 'Content-Type: application/json' -d '{ "rhash":"a5d29d8ee774353204b1aa164e23d5012187ebf5f2594f2698417ae2deeada5b" }'
```

This returns a public proof:

```json
{
    "block_height": 385,
    "chain": "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
    "csv_delay": 144,
    "event_id": "0325c1f003ea7e1d8dca701a4ac7129f85076805d0904a7ad2a9d2a92ce87981",
    "hashes": [
        "c391561468ae5f0f61af1d31df0e4702371691486362cb4e6a701aa1b3ab223c:8",
        "5ff8db7b96a1824bae0021303fb92cea1fc9ee33dcbf7d2fc4f8e21fb03ecded:12",
        "850232ebde515c54a6a0421ae6ca5a7ec2d8cf03380febb57db36557182f2993:80",
        "e4562c7bae164d97750c57eda0dd3240ff5170b836deda092625cbe848000123:17",
        "53b9bc1e430ec613a14f85c15955520533a07fc399e4e3a22febe524e86384a3:1536"
    ],
    "index": 11,
    "outpoint": "63422a2a719fcb043fa822dda925e6d80532a3da0d44014cb402613710ea0e36:0",
    "rhash": "a5d29d8ee774353204b1aa164e23d5012187ebf5f2594f2698417ae2deeada5b",
    "value": 16,
    "version": 0
}
```


verify_proof
============

If the proof is saved in $proof, we can use:

```bash
curl -X POST http://localhost:5455/api/verify_proof -H 'Content-Type: application/json' -d  @<(echo $proof)
```

This returns the value that was burnt for event_id and rhash.

```json
{
  "leaf_value": 16,
  "confirmations": 1,
  "total_value": 1669
}
```

`leaf_value` is the value burnt for event_id rhash.
`total value` is the value of the burnt utxo.
