# QRL Addresses  

## Structure

QRL addresses are structured in the following way:

| Name | Bytes         | Count  |      Description      |
|------| ------------- |:------:|-----------------------| 
| DESC | 0 .. 2        |   3    | Address Descriptor    |
| HASH | 3 .. 35       |  32    | SHA2-256(DESC+PK)      |
| VERH | 36 .. 40      |   4    | SHA2-256(HASH)[-4:]    |

- `PK` is public key
- `ePK` is the extended public key. This result from the concatenation of the descriptor with the public key (PK)

**Important**: 
- Addresses are composed by 37 _bytes_. This is the internal format used in any API or module.
- For representational purposes (i.e. user interface, debugging, logs), it is possible that the address is represented as a hexstring prefixed with Q (75 ascii characters). This is appropriate for user related purposes but will be rejected by the API.

## Descriptor

The address descriptor determines the signature scheme, hash function, etc.

| Name | Bits           | Count  |      Description      |
|------| ------------- |:------:|-----------------------| 
| HF   | 0 .. 3        |   4    | Hash Function         |
| SIG  | 4 .. 7        |   4    | Signature Scheme      |
| P1   | 8 .. 11       |   4    | Parameters 1          |
| P2   | 12 .. 15      |   4    | Parameters 2          |
| P3   | 16 .. 23      |   8    | Parameters 3          |

#### SIG - Signature Type

| Value | Description  |
|------| ------------- | 
| 0    | XMSS        |
| 1 .. 15    | Reserved - Future expansion        |

#### HF - Hash Function

| Value | Description  |
|------| ------------- | 
| 0    | SHA2-256      |
| 1    | SHAKE-128      |
| 2    | SHAKE-256      |
| 3 .. 15    | Reserved - Future expansion        |

#### SIG = XMSS



## Mnemonic

The address descriptor allows to determine the signature scheme, hash function, etc.
