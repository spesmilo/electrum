
TODO:

 - we only need the nostr id (and maybe the pubkey if we make it signed)

 - who should sign the notarization event?
   -> the notary, or the upvoter?
   -> the notary could include the upvoter pubkey
   -> the upvoter, that would be better

 - the proof is unstable until the tx is confirmed: it should be possible to repost 
   - we could create a link to the proof provider

 - if the proof is outside the event, we can include retweets
   -> notarize the event id
   -> the field is like "sig", but it is dynamic
   -> you do not need to be the author in order to notarize

   - we can add retweets to the proof:



 -> the proof can be similar
 -> the proof can be temporary or permanent
 "fee": [ value, merkle proof]


a nostr reaction is another event kind. it can be notarized too

{
  kind: 7,
  created_at: 1723861300,
  content: '+',
  tags: [
    ['e', 'XXX'], # event id
    ['p', 'YYY']  # event pubkey
  ]

  "id": xxxx   # liker_id
  "sig": xxxx   # liker sig
}


Proofs
======

proof = {
  "txoutput"         # txid:n for the op_return
  "block number"     #
  "merkle proof"     # list of hashes
}

the hash that is added to the proof is: event_id OR (event_id+u_p+u_sig)


Nostr event
===========

# new kind, similar to nostr reactions:

{
  kind: 777,
  created_at: timestamp,      # must match block
  content: json.dumps(proof),
  tags: [
    ['e', 'XXX'],  # event id
    ['p', 'YYY'],  # event pubkey
    ['v', int]     # upvote value in satoshis
    ['u_p', 'ZZZ']   # upvoter pubkey (optional)
    ['u_sig', 'ZZZ']   # upvoter signature (optional): sig(event_id)
  ]
  "id": xxxx        # id(pubkey, created_at, kind, tags, content)
  "pubkey": xxxx    # notary pubkey
  "sig": xxxx       # notary signature: sig(id)
}

# the notary provides a list of proofs
# the upvoter should sign
# the upvoter pubkey may be notarized


Event filtering
===============

-> client fetches a post with its reactions, using filters
-> client can agregate the fees in order to upvote

-> new type of event filter: 
   - filter by fee
   - filter by aggregated fee
   
API
===

 we could use keysend?

issues
=======
 to better fight spam, we should have something self contained
 -> package relaying?

----------------


 tx1 -> tx2
 tx1 -> tx2 -> tx3     # adding new tree tx3
 tx1'                  # adding new tree tx4

tx1 gets mined
 -> we need to check if its children were mined (we dont know it yet)
 -> we need to have a copy of tx4

 tx2 -> tx3     (tx4)
 tx2'

tx2 gets mined (after tx1):
 tx3 (tx4)
 tx3'


