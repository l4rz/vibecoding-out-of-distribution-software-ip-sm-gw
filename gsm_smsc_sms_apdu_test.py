#!/usr/bin/env python3
"""
GSM SMSC+TPDU APDU Test Script
==============================

This script accepts classic GSM PDUs that include an SMSC header:
  [SMSC_LEN][SMSC_TOA][SMSC_BCD...][TPDU...]

It strips the SMSC portion, prints basic SMSC info, and then decodes
the remaining TPDU using the existing TPDU decoder.
"""

import sys
import logging
from typing import Tuple, Optional

from gsm_sms_apdu import decode_gsm_sms_pdu, SMSMessage

logger = logging.getLogger(__name__)


def _normalize_hex(pdu_hex: str) -> str:
    return pdu_hex.strip().replace(" ", "").upper()


def _decode_bcd_digits(bcd_bytes: bytes) -> str:
    """Decode semi-octet swapped BCD digits (ignore 0xF filler nibbles)."""
    digits: list[str] = []
    for byte in bcd_bytes:
        low = byte & 0x0F
        high = (byte >> 4) & 0x0F
        if low != 0x0F:
            digits.append(str(low))
        if high != 0x0F:
            digits.append(str(high))
    return "".join(digits)


def strip_smsc_header(pdu_hex: str) -> Tuple[str, Optional[str], Optional[int]]:
    """
    Strip SMSC header and return (tpdu_hex, smsc_number, smsc_toa).
    smsc_number may be None if SMSC length is zero.
    """
    pdu_hex = _normalize_hex(pdu_hex)
    try:
        pdu = bytes.fromhex(pdu_hex)
    except ValueError as e:
        raise ValueError(f"Invalid hex input: {e}")

    if len(pdu) < 1:
        raise ValueError("PDU too short: missing SMSC length")

    smsc_len = pdu[0]  # number of bytes following (TOA + address)
    if len(pdu) < 1 + smsc_len:
        raise ValueError(
            f"PDU too short for SMSC: need {1 + smsc_len} bytes, have {len(pdu)}"
        )

    smsc_number: Optional[str] = None
    smsc_toa: Optional[int] = None
    if smsc_len > 0:
        smsc_ie = pdu[1 : 1 + smsc_len]
        if len(smsc_ie) < 1:
            raise ValueError("SMSC IE too short: missing TOA")
        smsc_toa = smsc_ie[0]
        smsc_digits = _decode_bcd_digits(smsc_ie[1:])
        # International (0x91) commonly means add '+'
        if smsc_toa == 0x91 and smsc_digits:
            smsc_number = f"+{smsc_digits}"
        else:
            smsc_number = smsc_digits or None

    tpdu = pdu[1 + smsc_len :]
    if len(tpdu) == 0:
        raise ValueError("Empty TPDU after stripping SMSC header")

    return tpdu.hex().upper(), smsc_number, smsc_toa


def print_sms_details(sms: SMSMessage):
    """Print detailed SMS information (mirror gsm_sms_apdu_test.py style)."""
    print("=" * 60)
    print(f"PDU TYPE: {sms.pdu_type}")
    print("=" * 60)

    if sms.tp_mr is not None:
        print(f"Message Reference: {sms.tp_mr}")
    if sms.tp_oa:
        print(f"FROM: {sms.tp_oa}")
    if sms.tp_da:
        print(f"TO: {sms.tp_da}")
    if hasattr(sms, "tp_ra") and sms.tp_ra:
        print(f"RECIPIENT: {sms.tp_ra}")
    if sms.tp_scts:
        print(f"TIMESTAMP: {sms.tp_scts}")
    if sms.tp_dt:
        print(f"DISCHARGE TIME: {sms.tp_dt}")
    if sms.tp_ud:
        print(f"TEXT: {sms.tp_ud}")

    if sms.tp_pid is not None:
        print(f"Protocol ID: 0x{sms.tp_pid:02X}")
    if sms.tp_dcs is not None:
        print(f"Data Coding Scheme: 0x{sms.tp_dcs:02X}")
    if sms.tp_udl is not None:
        print(f"User Data Length: {sms.tp_udl}")
    if sms.tp_st is not None:
        print(f"Status: 0x{sms.tp_st:02X}")
    if sms.tp_ud_hex:
        print(f"RAW DATA: {sms.tp_ud_hex}")
    print()


def main():
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Usage: python gsm_sms_smsc_apdu_test.py <hex_pdu1> [hex_pdu2] ...")
        print()
        print("Accepts classic GSM PDUs that start with an SMSC header.")
        sys.exit(1)

    for i, raw_hex in enumerate(sys.argv[1:], 1):
        raw_hex_norm = _normalize_hex(raw_hex)
        print(f"Testing PDU #{i}: {raw_hex_norm}")
        print(f"Length: {len(raw_hex_norm)} hex chars ({len(raw_hex_norm)//2} bytes)")
        try:
            tpdu_hex, smsc_number, smsc_toa = strip_smsc_header(raw_hex_norm)
            if smsc_number is not None or smsc_toa is not None:
                toa_str = f"0x{smsc_toa:02X}" if smsc_toa is not None else "n/a"
                print(f"SMSC TOA: {toa_str}")
                if smsc_number:
                    print(f"SMSC: {smsc_number}")
            print(f"TPDU HEX: {tpdu_hex}")
            sms = decode_gsm_sms_pdu(tpdu_hex)
            print_sms_details(sms)
        except Exception as e:
            logger.error("Failed to decode PDU: %s", e)
            print(f"ERROR: {e}")
            print()
            continue


if __name__ == "__main__":
    main()

