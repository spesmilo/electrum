The notary API has 3 public endpoints


notarize
========

Notarize takes an event_id and a public fee. The public fee must be a power of two.

```bash
curl -X POST http://localhost:5455/api/notarize -H 'Content-Type: application/json' -d '{ "event_id":"277419e0a32a8e2181f5b29102eb5008c53fec1b6d980d4b33d0a0aaadf44fc2", "fee":128 }' 
```

This returns a lightning invoice and a rhash:

```json
{
  "invoice": "lnbcrt80n1p507j4zpp5lyae3cm5v3w7nkxwu4vcx32dqr49g485prqrvk8vh764nxrajatqsp5p53uxxxwgwkuganeraeepkmvykfwqpthnavjndsuflcxf3u58jasdr8xuerjcejxvekxdpcvdnxgwfc8yenwwphv5ukzvfkvcmrzvtzvgmnsv348ycrvctpxgcnwerrx56nvctrv4jx2df4x5crjwt9v9skydqcqzynxqrrss9qlzqqqqqqqqqqqqqqqqqqqqqqqqqqysgqrzjq2xevues3u96zjnms0x9a69sf3lmxf0su6f6uyvfjt90p6gwfk4a6paec4eks2wj4vqqqqqqqqqqqqqqqyw3hkzdvce5afyud02k8l6ezvqmrk3sjmrlsz0ynrzwxf770qqpqheu9zjf64lzzdj25r8kx9nsvnnhyqew8v7qmgweu6l8tcc8h7yzgqdaexks",
  "rhash": "729c233c48cfd9893787e9a16f611bb7825906aa217dc556acede555099eaab4"
}
```

The notary will add his own fee to the public fee.
The lightning invoice amount is the sum of the public fee and the notary fee.
The public proof will be available after the invoice has been paid.


get_proof
=========

```bash
curl -X POST http://localhost:5455/api/get_proof -H 'Content-Type: application/json' -d '{ "rhash":"729c233c48cfd9893787e9a16f611bb7825906aa217dc556acede555099eaab4" }'
```

This returns a public proof:

```json
{
  "version": 0,
  "chain": "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
  "index": 1,
  "hashes": [
    "b9eaa51e8b95f6273e28772dc5278a55ac52c2488353df06fd50d8db1c2a1aa1"
    ],
  "event_id": "277419e0a32a8e2181f5b29102eb5008c53fec1b6d980d4b33d0a0aaadf44fc2",
  "rhash": "729c233c48cfd9893787e9a16f611bb7825906aa217dc556acede555099eaab4",
  "outpoint": "b18b07795821595b1208d3eabab95cc999f4697949ef6b7a4331b108d2361b4d:0",
  "roots": {
    "1": "960740337f11c02ede2ff6ead030275b214d0a2d773b73f273c14564876c4eb0",
    "3": "da10a274144212f5ea5993d8d18418d8c56d65240f749a73ba91797b2d0c470e",
    "6": "5c37e75f46a8c6f61a3f70b192f55187bb8f1ffe86fbdafec61c9a148b50ed27",
    "8": "af9fc921e1fa8b4986f13b8b500dc03f94088910ceb973bf4d72ffb9e43e9191"
  },
  "block_height": 229,
  "csv_delay": 1
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
  "leaf_value": 128,
  "confirmations": 151,
  "total_value": 330
}
```

`leaf_value` is the value burnt for event_id rhash.
`total value` is the value of the burnt utxo.
