#!/usr/bin/env python3
"""High-level SMS codec for IMS SIP MESSAGE bodies.

Previously relied on the smspdu package; now uses our custom
`gsm_rp_sms_apdu` (RP-DATA + TPDU) parser which internally relies on
`gsm_sms_apdu`.
"""

import logging
from typing import Dict
from gsm_rp_sms_apdu import decode_rp_sms_pdu

logger = logging.getLogger("ipsmgw")


def decode_vnd_sms(binary_body: bytes) -> Dict[str, str]:
    """Decode IMS SIP `application/vnd.3gpp.sms` binary payload.

    The payload is expected to contain a concatenated RP-DATA header and
    a GSM SMS TPDU. We return a simple dict for downstream routing.
    """
    logger.info("Attempting to decode IMS SMS payload (%d bytes)", len(binary_body))
    hex_pdu = binary_body.hex().upper()
    logger.debug("SMS payload (hex): %s", hex_pdu)

    try:
        rp_msg = decode_rp_sms_pdu(hex_pdu)
        tp = rp_msg.tpdu

        sms_type = tp.pdu_type
        sender = str(tp.tp_oa or rp_msg.rp_oa or "unknown")
        recipient = str(tp.tp_da or rp_msg.rp_da or "unknown")
        text = tp.tp_ud or ""
        ref = getattr(tp, "tp_mr", 0)

        result = {
            "type": sms_type,
            "from": sender,
            "to": recipient,
            "text": text,
            "ref": ref,
        }
        logger.info("Decoded IMS SMS: %s", result)
        return result

    except Exception as e:
        logger.exception("Failed to decode IMS SMS payload: %s", e)
        return {
            "type": "UNKNOWN",
            "from": "unknown",
            "to": "unknown",
            "text": "decode_error",
            "ref": 0,
        } 