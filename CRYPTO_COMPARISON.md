# Traditional vs Post-Quantum Crypto

## 1
Traditional crypto = lock quantum can pick 
Post-quantum = puzzle quantum can't solve 

## 2

| Traditional | Post-Quantum |
|-------------|--------------|
| RSA, ECDHE | Kyber, NTRU |
| Small keys (384 bits) | Big keys (1568+ bytes) |
| Quantum breaks it| Quantum safe  |

## 3

```
ECDHE (traditional):  384 bits  / Works
Kyber-1024 (PQ):     1568 bytes / Works  
NTRU/HQC (PQ):       7245 bytes / Works
```

## 4

```
Now:     Your Bank → RSA → Quantum = HACKED 
Future:  Your Bank → Kyber → Quantum = SAFE 
```

## 5
Post-quantum = bigger keys, but quantum can't crack them

