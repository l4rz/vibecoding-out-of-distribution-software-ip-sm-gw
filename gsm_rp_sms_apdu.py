#!/usr/bin/env python3
"""GSM RP-DATA + SMS-TPDU concatenated APDU parser.

IMS SMS PDUs transported over SIP (ETSI TS 24.341) carry two
concatenated layers:
1. GSM A-I/F RP-DATA (3GPP TS 24.011)
2. GSM SMS TPDU (3GPP TS 23.040/03.40)

This module parses the RP section to extract the destination/originator
addresses and the embedded TPDU – which is then decoded with the
existing `gsm_sms_apdu` parser.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Tuple

from gsm_sms_apdu import decode_gsm_sms_pdu, SMSMessage
from gsm_sms_apdu import encode_gsm_sms_deliver, ADDR_TYPE_INTERNATIONAL

logger = logging.getLogger(__name__)

# RP-Message types (only RP-DATA handled for now)
RP_DATA_MT = 0x00  # Mobile-Terminated (SC → MS)
RP_DATA_MO = 0x01  # Mobile-Originated (MS → SC)

@dataclass
class RPAddress:
    type_of_address: int  # TON/NPI octet (same as TP TOA)
    digits: str           # decoded number (BCD semi-octet swapped)

    def __str__(self):
        if self.type_of_address == 0x91:  # international
            return f"+{self.digits}"
        return self.digits

@dataclass
class RPSMSMessage:
    """Decoded RP-DATA + TPDU message"""
    rp_mti: int               # message type 0x00 / 0x01 / 0x02 (ACK)
    rp_mr: int                # message reference
    rp_oa: Optional[RPAddress]
    rp_da: Optional[RPAddress]
    tpdu: SMSMessage          # nested TPDU

# ---------------------------------------------------------------------------
# Helper – BCD semi-octet decoding (copied from gsm_sms_apdu but standalone)
# ---------------------------------------------------------------------------

def _decode_bcd(bcd_bytes: bytes, digit_count: int) -> str:
    digits: list[str] = []
    consumed = 0
    for byte in bcd_bytes:
        if consumed >= digit_count:
            break
        low = byte & 0x0F
        high = (byte >> 4) & 0x0F
        if low != 0x0F:
            digits.append(str(low))
            consumed += 1
        if consumed >= digit_count:
            break
        if high != 0x0F:
            digits.append(str(high))
            consumed += 1
    return ''.join(digits)

# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _encode_bcd_from_digits(number: str) -> bytes:
    """Encode numeric string into semi-octet swapped BCD octets (low nibble first).
    Pads with 0xF if odd number of digits.
    """
    digits_only = ''.join(ch for ch in number if ch.isdigit())
    nibbles = [int(d) for d in digits_only]
    if len(nibbles) % 2 == 1:
        nibbles.append(0xF)
    out = bytearray()
    for i in range(0, len(nibbles), 2):
        low = nibbles[i] & 0x0F
        high = nibbles[i + 1] & 0x0F
        out.append((high << 4) | low)
    return bytes(out)

def _encode_rp_address_ie(number: Optional[str], toa: int = ADDR_TYPE_INTERNATIONAL) -> bytes:
    """Encode RP address information element: [len][TOA][BCD...].

    If number is falsy, encodes zero-length address IE (single 0x00 length octet).
    Length counts the TOA + BCD octets.
    """
    if not number:
        return bytes([0x00])
    bcd = _encode_bcd_from_digits(number)
    length = 1 + len(bcd)
    return bytes([length & 0xFF, toa & 0xFF]) + bcd

def encode_rp_header(
    *,
    rp_mti: int,
    rp_mr: int,
    rp_oa_number: Optional[str] = None,
    rp_da_number: Optional[str] = None,
    rp_oa_toa: int = ADDR_TYPE_INTERNATIONAL,
    rp_da_toa: int = ADDR_TYPE_INTERNATIONAL,
) -> bytes:
    """Build RP-DATA header (without RP-UD and without its length octet).

    Returns bytes: [RP-MTI][RP-MR][RP-OA][RP-DA]
    """
    result = bytearray()
    result.append(rp_mti & 0xFF)
    result.append(rp_mr & 0xFF)
    result.extend(_encode_rp_address_ie(rp_oa_number, rp_oa_toa))
    result.extend(_encode_rp_address_ie(rp_da_number, rp_da_toa))
    return bytes(result)

def encode_rp_concat_with_tpdu(
    tpdu_hex: str,
    *,
    rp_mti: int = RP_DATA_MO,
    rp_mr: int = 0x02,
    rp_oa_number: Optional[str] = None,
    rp_da_number: Optional[str] = None,
    rp_oa_toa: int = ADDR_TYPE_INTERNATIONAL,
    rp_da_toa: int = ADDR_TYPE_INTERNATIONAL,
) -> str:
    """Encode full RP-DATA with given TPDU (as hex) and return concatenated hex string.

    Adds RP-UD length octet before TPDU, per 24.011.
    """
    tpdu_bytes = bytes.fromhex(tpdu_hex.strip())
    header = encode_rp_header(
        rp_mti=rp_mti,
        rp_mr=rp_mr,
        rp_oa_number=rp_oa_number,
        rp_da_number=rp_da_number,
        rp_oa_toa=rp_oa_toa,
        rp_da_toa=rp_da_toa,
    )
    rp = bytearray()
    rp.extend(header)
    rp.append(len(tpdu_bytes) & 0xFF)  # RP-UD length
    rp.extend(tpdu_bytes)
    return bytes(rp).hex().upper()

def build_rp_mo_with_sms_deliver(
    *,
    oa_number: str,
    text: str,
    pid: int = 0x00,
    dcs: int = 0x00,
    rp_mr: int = 0x02,
    rp_da_number: Optional[str] = None,
) -> Tuple[str, str, str]:
    """Convenience builder: create SMS-DELIVER TPDU, RP-DATA-MO header, and full RP+TPDU.

    Returns tuple of (tpdu_hex, rp_header_hex, concatenated_hex).
    """
    tpdu_hex = encode_gsm_sms_deliver(oa_number, text, pid=pid, dcs=dcs)
    rp_header = encode_rp_header(
        rp_mti=RP_DATA_MO,
        rp_mr=rp_mr,
        rp_oa_number=oa_number,
        rp_da_number=rp_da_number,
    ).hex().upper()
    concatenated = encode_rp_concat_with_tpdu(
        tpdu_hex,
        rp_mti=RP_DATA_MO,
        rp_mr=rp_mr,
        rp_oa_number=oa_number,
        rp_da_number=rp_da_number,
    )
    return tpdu_hex, rp_header, concatenated

# ---------------------------------------------------------------------------
# Core decode
# ---------------------------------------------------------------------------

def decode_rp_sms_pdu(hex_pdu: str) -> RPSMSMessage:
    """Parse concatenated RP-DATA + TPDU APDU and return structured object.

    Supports RP-DATA (MT/MO) carrying a TPDU, and RP-ACK which may carry an
    SMS-DELIVER-REPORT TPDU in its RP-User-Data.
    """
    hex_pdu = hex_pdu.strip().replace(" ", "").upper()
    pdu = bytes.fromhex(hex_pdu)
    idx = 0

    if len(pdu) < 3:
        raise ValueError("PDU too short for RP header")

    rp_mti = pdu[idx]
    idx += 1
    raw_rp_mr = pdu[idx]   # preserve original message reference
    idx += 1

    # RP-ACK (MS → Network). Structure: [MTI=0x02][MR][RP-UD-Len][TPDU...]
    if rp_mti == 0x02:
        if idx >= len(pdu):
            raise ValueError("Missing RP-UD length in RP-ACK")
        ud_len = pdu[idx]
        idx += 1
        #if idx + ud_len > len(pdu):
        #    raise ValueError("PDU too short for RP-ACK RP-UD")
        tpdu_bytes = pdu[idx: idx + ud_len]
        tpdu = decode_gsm_sms_pdu(tpdu_bytes.hex())
        return RPSMSMessage(
            rp_mti=rp_mti,
            rp_mr=raw_rp_mr,
            rp_oa=None,
            rp_da=None,
            tpdu=tpdu,
        )

    # RP-Originator Address length
    oa_len = pdu[idx]
    idx += 1

    rp_oa: Optional[RPAddress] = None
    if oa_len:
        if idx + oa_len > len(pdu):
            raise ValueError("PDU too short for RP-OA")
        oa_bytes = pdu[idx: idx + oa_len]
        idx += oa_len
        oa_toa = oa_bytes[0]
        oa_digits = _decode_bcd(oa_bytes[1:], (oa_len - 1) * 2)
        rp_oa = RPAddress(oa_toa, oa_digits)

    # RP-Destination Address length
    if idx >= len(pdu):
        raise ValueError("Missing RP-DA length")
    da_len = pdu[idx]
    idx += 1

    rp_da: Optional[RPAddress] = None
    if da_len:
        if idx + da_len > len(pdu):
            raise ValueError("PDU too short for RP-DA")
        da_bytes = pdu[idx: idx + da_len]
        idx += da_len
        da_toa = da_bytes[0]
        da_digits = _decode_bcd(da_bytes[1:], (da_len - 1) * 2)
        rp_da = RPAddress(da_toa, da_digits)

    # RP-User-Data length and value
    if idx >= len(pdu):
        raise ValueError("Missing RP-UD length")
    ud_len = pdu[idx]
    idx += 1
    if idx + ud_len > len(pdu):
        raise ValueError("PDU too short for RP-UD")
    tpdu_bytes = pdu[idx: idx + ud_len]

    # Decode nested TPDU
    tpdu = decode_gsm_sms_pdu(tpdu_bytes.hex())

    return RPSMSMessage(
        rp_mti=rp_mti,
        rp_mr=raw_rp_mr,
        rp_oa=rp_oa,
        rp_da=rp_da,
        tpdu=tpdu,
    )

# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys, pprint
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) != 2:
        print("Usage: python gsm_rp_sms_apdu.py <hex_pdu>")
        sys.exit(1)
    msg = decode_rp_sms_pdu(sys.argv[1])
    pprint.pp(msg) 