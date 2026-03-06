# Wireshark Analysis

## TL;DR
Wireshark sees the "hello" but NOT your secret messages! 🔐

## How to Capture
1. Open Wireshark → Loopback interface
2. Filter: `tcp.port == 8443`
3. Run: `python encryption_compare.py`

## What You See

| Step | Packet | Can Read? |
|------|--------|-----------|
| 1 | TCP handshake (SYN/SYN-ACK/ACK) | YES |
| 2 | Client Hello | YES |
| 3 | Server Hello | YES |
| 4 | Certificate | YES |
| 5 | Key Exchange | YES |
| 6 | Application Data | **NO** ❌ |

## Key Facts
- **Cipher**: AES-256-GCM (super secure!)
- **Forward Secrecy**: Yes (quantum can't retroactively decrypt)
- **Your password**: Hidden (encrypted!)

