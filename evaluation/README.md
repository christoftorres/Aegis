
### Reentrancy Evaluation

###### Test 1

```
(DAO) (Mainnet)

python3 aegis.py -t 0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b
```

```
(SpankChain) (Mainnet)

python3 aegis.py -t 0x21e9d20b57f6ae60dac23466c8395d47f42dc24628e5a31f224567a2b4effa88
```

```
(SimpleDAO) (Ropsten)

python3 aegis.py -t 0x0c2eb9a602a0b6493a67784534f066c20895fd5b8dc4ecd495520888ce4ff92e
```

```
(Cross-Function Reentrancy) (Ropsten)

python3 aegis.py -t 0x73af82a5b067495a368a0c3e2b96936cc18680ca07fe11df41ea8a3865e08353
```

```
(Delegated Reentrancy) (Ropsten)

python3 aegis.py -t 0xeec548c6f235e191440954ac32d2d20c90c482271a76bdf2545d9513a3a46f83
```

```
(Create-Based Reentrancy) (Ropsten)

python3 aegis.py -t 0x69feed59fadaedc67f1ba9d09f720ecc74470f77a0f89fa5f9842b32990034f0 
```

###### Test 2

| Testcase \ Tool            | ECFChecker | Sereum    | ÆGIS | Transaction
| ---------------------------| ---------- | --------- | ----- | -----------
| NoLock + SameFunction      | TP         | TP        | TP    |  0x02593d40eb1b13ce35b3f43bd4af743fd75c041cafb70ac5e3c94e77e08b4591 |
| NoLock + CrossFunction     | FN         | TP        | TP    | 0xaacf700ba687888f9796bb33ec3bf80380acae5941aa861d471444fecf766fc6 |
| BuggyLock + SameFunction   | TN         | FP        | TN    | 0x63b07a8fc9aa635cc04b450497f9dcd76059b175b84f549a420a0374b0494e01 |
| BuggyLock + CrossFunction  | FN         | TP        | TP    | 0x1aaaa0ee72ec14cf86ba4273a415e88498293dffe51b8883bf8ebd24e6066de0 |
| SecureLock + SameFunction  | TN         | FP        | TN    | 0xcd03355bfdf1650c846c200741b94d1f7d0af1450ebf72c8e0156f5ee1aabf59 |
| SecureLock + CrossFunction | TN         | FP        | TN    | 0xa735288c921e987c6b3cf94cdef03d8c31284ace1583a16f6a887efab22c4f49 |

###### Test 3

```
(Unconditional Reentrancy) (Mainnet)

python3 aegis.py -t 0xebeabdcfbe897a78baba0d0720b7d208c2472d36f06669bdb5b319715bc0b7f5
```

### Access Control Evaluation

###### Test 1 (Parity Wallet Hack 1 - 19.07.2017)

```
(ParityWallet) (Mainnet)

tx0 - initWallet() (0x9dbf0326a03a2a3719c27be4fa69aacc9857fd231a8d9dcaede4bb083def75ec)
tx1 - execute() (0xeef10fc5170f669b86c4cd0444882a96087221325f8bf2f55d6188633aa7be7c)

python3 aegis.py -c 0xbec591de75b8699a3ba52f073428822d0bfc0d7e
```

###### Test 2 (Parity Wallet Hack 2 - 06.11.2017)

```
(WalletLibrary) (Mainnet)

tx0 - initWallet() (0x05f71e1b2cb4f03e547739db15d080fd30c989eda04d37ce6264c5686e0722c9)
tx1 - kill() (0x47f7cff7a5e671884629c93b368cb18f58a993f4b19c2a53a8662e3f1482f690)

python3 aegis.py -c 0x863df6bfa4469f3ead0be8f9f2aae51c91a907b4
```
