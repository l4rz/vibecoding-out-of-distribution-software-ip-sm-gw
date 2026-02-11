#!/usr/bin/env python3
"""Utility to build GSM RP-ACK + SMS-SUBMIT-REPORT payloads for IMS SMS."""
from __future__ import annotations

from typing import Tuple

from gsm_sms_apdu import SMSMessage

__all__ = [
    "build_submit_report_tpdu",
    "build_rp_ack_payload",
]

# ---------------------------------------------------------------------------
# GSM TPDU helpers
# ---------------------------------------------------------------------------

def build_submit_report_tpdu(tp_mr: int = 0, success: bool = True, tp_fcs: int = 0x80) -> bytes:
    """Return bytes of a minimal SMS-SUBMIT-REPORT TPDU (23 040 §9.2.2.2a).

    success=True   → positive report (only two octets: MTI+PI)
    success=False  → negative report (MTI, FCS, PI)

    *TP-MR is **not present** in submit-report per spec – the SC already
    knows the reference it gave; many examples still put TP-FCS immediately
    after the first octet for failure cases.*
    """
    import datetime

    def _bcd_swap(val: int) -> int:
        return ((val % 10) << 4) | (val // 10)

    def _encode_scts(dt: datetime.datetime) -> bytes:
        return bytes([
            _bcd_swap(dt.year % 100),
            _bcd_swap(dt.month),
            _bcd_swap(dt.day),
            _bcd_swap(dt.hour),
            _bcd_swap(dt.minute),
            _bcd_swap(dt.second),
            0x00  # timezone = 0 (UTC)
        ])

    first_octet = 0x01  # MTI = 01 (SMS-SUBMIT-REPORT), all flags 0

    if success:
        # success: include TP-MR, PI indicating SCTS present (bit2), then SCTS
        pi = 0x04  # bit2 set → TP-SCTS present
        pi = 0x00 # 
        scts = _encode_scts(datetime.datetime.utcnow())
        # return bytes([first_octet, tp_mr & 0xFF, pi]) + scts # WE DONT NEED TP-MR CRAP IT BREAKS PDU
    return bytes([first_octet, pi]) + scts

    # Failure report -> TP-MR, TP-FCS, PI
    return bytes([first_octet, tp_fcs & 0xFF, 0x00])

# ---------------------------------------------------------------------------
# RP-ACK builder
# ---------------------------------------------------------------------------

def build_rp_ack_payload(rp_mr: int, tpdu_submit: SMSMessage, ok: bool = True, tp_cause: int = 0x00) -> bytes:
    """Create concatenated RP-ACK + SMS-SUBMIT-REPORT bytes.

    rp_mr        – Message-Reference from original RP-DATA
    tpdu_submit  – Parsed SMS-SUBMIT TPDU (we copy TP-MR)
    ok           – success (True) or error (False)
    tp_cause     – TP-FCS value when ok=False (ignored when ok=True)
    """
    submit_report = build_submit_report_tpdu(tpdu_submit.tp_mr or 0, success=ok, tp_fcs=tp_cause)

    # RP layer (24 011 §8.2.2.1.2)
    rp_message_type = 0x03   # RP-ACK Network→MS

    if submit_report:
        rp_ud_ie = 0x41
        rp_ud_len = len(submit_report)
        rp_header = bytes([
            rp_message_type,
            rp_mr & 0xFF,
            rp_ud_ie,
            rp_ud_len & 0xFF,
        ])
        return rp_header  + submit_report

    # If for some reason TPDU empty, just ACK header (rare)
    return bytes([rp_message_type, rp_mr & 0xFF]) 