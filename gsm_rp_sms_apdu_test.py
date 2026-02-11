#!/usr/bin/env python3
"""Test runner for RP+SMS concatenated APDUs."""

import sys
import logging
from gsm_rp_sms_apdu import decode_rp_sms_pdu

logging.basicConfig(level=logging.INFO)

if len(sys.argv) < 2:
    print("Usage: python gsm_rp_sms_apdu_test.py <hex_pdu1> [hex_pdu2] ...")
    sys.exit(1)

for pdu_hex in sys.argv[1:]:
    print(f"Testing PDU: {pdu_hex}")
    msg = decode_rp_sms_pdu(pdu_hex)

    print("=" * 60)
    print(f"RP Message Type: 0x{msg.rp_mti:02X}  MR: {msg.rp_mr}")
    if msg.rp_oa:
        print(f"RP-OA: {msg.rp_oa}")
    if msg.rp_da:
        print(f"RP-DA: {msg.rp_da}")

    tp = msg.tpdu
    print("-" * 60)
    print(f"TPDU TYPE: {tp.pdu_type}")
    if tp.tp_da:
        print(f"TP-DA: {tp.tp_da}")
    if tp.tp_oa:
        print(f"TP-OA: {tp.tp_oa}")
    if tp.tp_scts:
        print(f"TIMESTAMP: {tp.tp_scts}")
    if tp.tp_ud:
        print(f"TEXT: {tp.tp_ud}")
    print("=" * 60) 