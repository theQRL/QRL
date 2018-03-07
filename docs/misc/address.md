# QRL Addresses  

## Structure

QRL addresses are structured in the following way:

| Name | Bytes         | Count  |      Description      |
|------| ------------- |:------:|-----------------------| 
| DESC | 0 .. 2        |   3    | Address Descriptor    |
| DATA | 3 .. N        |  ??    | N will depend on the address format      |

## Descriptor

The address descriptor determines the address format, signature scheme, hash function, etc.

| Name | Bits           | Count  |      Description      |
|------| ------------- |:------:|-----------------------| 
| HF   | 0 .. 3        |   4    | Hash Function         |
| SIG  | 4 .. 7        |   4    | Signature Scheme      |
| P1   | 8 .. 11       |   4    | Parameters 1 (ie. height, etc.)  |
| P2   | 12 .. 15      |   4    | Address Format        |
| P3   | 16 .. 23      |   8    | Parameters 2          |

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

#### AF - Address Format

| Value | Description  |
|------| ------------- | 
| 0    | SHA256_2X     |
| 1 .. 15    | Reserved - Future expansion        |

## Address Format

### Format: SHA256_2X

| Name | Bytes         | Count  |      Description      |
|------| ------------- |:------:|-----------------------| 
| DESC | 0 .. 2        |   3    | Address Descriptor    |
| HASH | 3 .. 35       |  32    | SHA2-256(DESC+PK)      |
| VERH | 36 .. 40      |   4    | SHA2-256(HASH) (only last 4 bytes)   |

- `PK` (32 bytes) is public key
- `ePK` (35 bytes) is the extended public key, i.e. DESC+PK

**Important**: 
- Addresses are composed by 39 _bytes_. This is the internal format used in any API or module.
- For representational purposes (i.e. user interface, debugging, logs), it is possible that the address is represented as a hexstring prefixed with Q (79 ascii characters). This is appropriate for user related purposes but will be rejected by the API.
- It is recommended that block explorer, web-wallet and other components show addresses with the Q prefix to users. 
- It is possible to determine valid addresses by checking the descriptor and VERH bytes. 

## Signature Schemes

### XMSS

In the case of using XMSS. The parameters are used as follows:

| Name | Bits           | Count  |      Description     |
|------| ------------- |:------:|-----------------------| 
| HF   | 0 .. 3        |   4    | SHA2-256, SHAKE128, SHAKE256 |
| SIG  | 4 .. 7        |   4    | XMSS                  |
| P1   | 8 .. 11       |   4    | XMSS Height / 2       |
| AF   | 12 .. 15      |   4    | Address Format        |
| P2   | 16 .. 23      |   8    | Not used              |

## Seed / Extended Seed

**Seed** (48 bytes): Not presented to users. Users instead have access to the _extended seed_.

_Important_: The seed is not enough to reconstruct an address because it does not include information about the signature scheme and corresponding parameters.

**Extended Seed** (51 bytes): User typically have access to a composed seed that include the descriptor as a prefix.

**HexSeed** (102 bytes): Extended seed represented as a hexadecimal number in ASCII characters. This is used for representational purposes and never used in the code or API.

**Mnemonic** (34 words): Each word represents 12-bits. A mnemonic can be converted to an **Extended Seed**
