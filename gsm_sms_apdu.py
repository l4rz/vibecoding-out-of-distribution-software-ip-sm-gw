#!/usr/bin/env python3
"""
GSM SMS APDU Parser
===================

A lightweight GSM SMS TPDU (GSM 03.40) parser for Python 3.
Implements SMS-SUBMIT, SMS-DELIVER, and SMS-STATUS-REPORT dissection.

Based on GSM 03.40 specification and Wireshark packet-gsm_sms.c implementation.
"""

import struct
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# GSM 03.40 TPDU Message Types
TPDU_MT_SMS_DELIVER = 0x00
TPDU_MT_SMS_SUBMIT = 0x01
TPDU_MT_SMS_COMMAND = 0x02
TPDU_MT_SMS_STATUS_REPORT = 0x03
TPDU_MT_SMS_DELIVER_REPORT = 0x04
TPDU_MT_SMS_SUBMIT_REPORT = 0x05

# Address Type Indicators
ADDR_TYPE_UNKNOWN = 0x00
ADDR_TYPE_INTERNATIONAL = 0x91
ADDR_TYPE_NATIONAL = 0xA1
ADDR_TYPE_ALPHANUMERIC = 0xD0

# Data Coding Scheme
DCS_7BIT = 0x00
DCS_8BIT = 0x04
DCS_UCS2 = 0x08

@dataclass
class SMSAddress:
    """SMS Address (TP-OA, TP-DA)"""
    type: int
    number: str
    is_alphanumeric: bool = False
    
    def __str__(self):
        if self.is_alphanumeric:
            return f"<{self.number}>"
        elif self.type == ADDR_TYPE_INTERNATIONAL:
            return f"+{self.number}"
        else:
            return self.number

@dataclass
class SMSTimestamp:
    """SMS Timestamp (TP-SCTS, TP-DT)"""
    year: int
    month: int
    day: int
    hour: int
    minute: int
    second: int
    timezone_offset: int  # in minutes
    
    def to_datetime(self) -> datetime:
        """Convert to Python datetime object"""
        # GSM years are 2-digit, assume 20xx for years < 50, 19xx for years >= 50
        if self.year < 50:
            year = 2000 + self.year
        else:
            year = 1900 + self.year
            
        # Create datetime with timezone offset
        dt = datetime(year, self.month, self.day, self.hour, self.minute, self.second)
        if self.timezone_offset != 0:
            dt = dt - timedelta(minutes=self.timezone_offset)
        return dt
    
    def __str__(self):
        dt = self.to_datetime()
        return dt.strftime("%m/%d/%Y %I:%M:%S %p")

@dataclass
class SMSMessage:
    """Decoded SMS Message"""
    pdu_type: str
    tp_mti: int
    tp_mr: Optional[int] = None
    tp_oa: Optional[SMSAddress] = None
    tp_da: Optional[SMSAddress] = None
    tp_ra: Optional[SMSAddress] = None
    tp_pid: Optional[int] = None
    tp_dcs: Optional[int] = None
    tp_scts: Optional[SMSTimestamp] = None
    tp_dt: Optional[SMSTimestamp] = None
    tp_ud: Optional[str] = None
    tp_udl: Optional[int] = None
    tp_st: Optional[int] = None
    tp_mms: Optional[bool] = None
    tp_lp: Optional[bool] = None
    tp_srr: Optional[bool] = None
    tp_vpf: Optional[int] = None
    tp_rd: Optional[bool] = None
    tp_fcs: Optional[int] = None
    tp_pi: Optional[int] = None
    tp_scts_relative: Optional[int] = None
    tp_dt_relative: Optional[int] = None
    tp_ud_hex: Optional[str] = None

class GSMSMSAPDU:
    """GSM SMS APDU Parser"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Precompute reverse map for GSM 7-bit alphabet for encoder
        self._gsm7_alphabet = (
            '@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !"#¤%&\'()*+,-./'
            '0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿'
            'abcdefghijklmnopqrstuvwxyzäöñüà'
        )
        self._gsm7_encode_map: dict[str, int] = {ch: idx for idx, ch in enumerate(self._gsm7_alphabet)}
    
    def decode_pdu(self, hex_pdu: str) -> SMSMessage:
        """Decode GSM SMS PDU from hex string"""
        try:
            # Remove any whitespace and convert to uppercase
            hex_pdu = hex_pdu.strip().upper()
            
            # Convert hex to bytes
            pdu_bytes = bytes.fromhex(hex_pdu)
            
            self.logger.debug(f"PDU bytes: {pdu_bytes.hex().upper()}")
            self.logger.debug(f"PDU length: {len(pdu_bytes)} bytes")
            
            # Parse the PDU
            return self._parse_tpdu(pdu_bytes)
            
        except Exception as e:
            self.logger.error(f"Failed to decode PDU: {e}")
            raise

    # ---------------------------------------------------------------------
    # ENCODING – TPDU (SMS-DELIVER) aka MT SMS
    # ---------------------------------------------------------------------
    def encode_sms_deliver(
        self,
        originating_address: str,
        user_data_text: str,
        *,
        pid: int = 0x00,
        dcs: int = 0x00,
        scts_dt: Optional[datetime] = None,
        originating_addr_type: int = ADDR_TYPE_INTERNATIONAL,
        deliver_flags_octet0: int = 0x24,
    ) -> bytes:
        """Build an SMS-DELIVER (aka MT SMS) TPDU.

        - originating_address: TP-OA numeric string (e.g. '18051234567' or '+1...')
        - user_data_text: message body to encode
        - pid: TP-PID (default 0x00)
        - dcs: TP-DCS (default 0x00 for GSM 7-bit)
        - scts_dt: datetime for TP-SCTS; defaults to now() with local tz offset
        - originating_addr_type: TOA, default international (0x91)
        - deliver_flags_octet0: first octet; default 0x24 to mirror reference samples
        """

        if scts_dt is None:
            scts_dt = datetime.now().astimezone()

        # First octet with flags (MTI=0 for SMS-DELIVER)
        first_octet = deliver_flags_octet0 & 0xFC  # ensure MTI bits are 00

        # TP-OA
        oa_bytes = self._encode_tp_address(originating_address, originating_addr_type)

        # TP-PID and TP-DCS
        tp_pid = pid & 0xFF
        tp_dcs = dcs & 0xFF

        # TP-SCTS
        scts_bytes = self._encode_timestamp(scts_dt)

        # TP-UDL and TP-UD
        if (tp_dcs & 0x0C) == 0x00:
            # 7-bit default alphabet
            ud_bytes, udl = self._encode_7bit(user_data_text)
        elif (tp_dcs & 0x0C) == 0x04:
            # 8-bit data
            ud_bytes = user_data_text.encode('latin1', errors='replace')
            udl = len(ud_bytes)
        elif (tp_dcs & 0x0C) == 0x08:
            # UCS2
            ud_bytes = user_data_text.encode('utf-16be', errors='replace')
            udl = len(ud_bytes)
        else:
            # Fallback to 8-bit
            ud_bytes = user_data_text.encode('latin1', errors='replace')
            udl = len(ud_bytes)

        # Assemble TPDU
        result = bytearray()
        result.append(first_octet)
        result.extend(oa_bytes)
        result.append(tp_pid)
        result.append(tp_dcs)
        result.extend(scts_bytes)
        result.append(udl & 0xFF)
        result.extend(ud_bytes)
        return bytes(result)
    
    def _parse_tpdu(self, pdu_bytes: bytes) -> SMSMessage:
        """Parse TPDU from bytes"""
        if len(pdu_bytes) < 1:
            raise ValueError("PDU too short")
        
        # Extract message type indicator (MTI)
        tp_mti = pdu_bytes[0] & 0x03
        
        self.logger.debug(f"TPDU MTI: {tp_mti}")
        
        if tp_mti == TPDU_MT_SMS_DELIVER:
            return self._parse_sms_deliver(pdu_bytes)
        elif tp_mti == TPDU_MT_SMS_SUBMIT:
            return self._parse_sms_submit(pdu_bytes)
        elif tp_mti == TPDU_MT_SMS_STATUS_REPORT:
            return self._parse_sms_status_report(pdu_bytes)
        elif tp_mti == TPDU_MT_SMS_COMMAND:
            # Interpret MTI==0x02 here as SMS-DELIVER-REPORT (MS->SC)
            return self._parse_sms_deliver_report(pdu_bytes)
        else:
            raise ValueError(f"Unsupported TPDU type: {tp_mti}")
    
    def _parse_sms_deliver(self, pdu_bytes: bytes) -> SMSMessage:
        """Parse SMS-DELIVER TPDU (GSM 03.40 section 9.2.2.1)"""
        self.logger.debug("Parsing SMS-DELIVER")
        
        offset = 1  # Skip MTI byte
        
        # Parse TP-MMS (More Messages to Send)
        tp_mms = bool(pdu_bytes[0] & 0x04)
        
        # Parse TP-LP (Loop Prevention)
        tp_lp = bool(pdu_bytes[0] & 0x08)
        
        # Parse TP-RP (Reply Path)
        tp_rp = bool(pdu_bytes[0] & 0x40)
        
        # Parse TP-UDHI (User Data Header Indicator)
        tp_udhi = bool(pdu_bytes[0] & 0x40)
        
        # Parse TP-SRI (Status Report Indication)
        tp_sri = bool(pdu_bytes[0] & 0x20)
        
        self.logger.debug(f"SMS-DELIVER flags: MMS={tp_mms}, LP={tp_lp}, RP={tp_rp}, UDHI={tp_udhi}, SRI={tp_sri}")
        
        # Parse TP-OA (Originator Address)
        tp_oa, offset = self._parse_address(pdu_bytes, offset)
        
        # Parse TP-PID (Protocol Identifier)
        tp_pid = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-DCS (Data Coding Scheme)
        tp_dcs = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-SCTS (Service Centre Time Stamp)
        tp_scts, offset = self._parse_timestamp(pdu_bytes, offset)
        
        # Parse TP-UDL (User Data Length)
        tp_udl = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-UD (User Data)
        tp_ud = None
        tp_ud_hex = None
        if tp_udl > 0 and offset < len(pdu_bytes):
            is_7bit = (tp_dcs & 0x0C) == 0
            ud_octets = (tp_udl * 7 + 7)//8 if is_7bit else tp_udl
            ud_bytes = pdu_bytes[offset:offset + ud_octets]
            tp_ud_hex = ud_bytes.hex().upper()
            tp_ud = self._decode_user_data(ud_bytes, tp_dcs, tp_udl)
        
        return SMSMessage(
            pdu_type="SMS-DELIVER",
            tp_mti=TPDU_MT_SMS_DELIVER,
            tp_mms=tp_mms,
            tp_lp=tp_lp,
            tp_oa=tp_oa,
            tp_pid=tp_pid,
            tp_dcs=tp_dcs,
            tp_scts=tp_scts,
            tp_udl=tp_udl,
            tp_ud=tp_ud,
            tp_ud_hex=tp_ud_hex
        )
    
    def _parse_sms_submit(self, pdu_bytes: bytes) -> SMSMessage:
        """Parse SMS-SUBMIT TPDU (GSM 03.40 section 9.2.2.2)"""
        self.logger.debug("Parsing SMS-SUBMIT")
        
        offset = 1  # Skip MTI byte
        
        # Parse TP-RD (Reject Duplicates)
        tp_rd = bool(pdu_bytes[0] & 0x04)
        
        # Parse TP-VPF (Validity Period Format)
        tp_vpf = (pdu_bytes[0] & 0x18) >> 3
        
        # Parse TP-RP (Reply Path)
        tp_rp = bool(pdu_bytes[0] & 0x40)
        
        # Parse TP-UDHI (User Data Header Indicator)
        tp_udhi = bool(pdu_bytes[0] & 0x40)
        
        # Parse TP-SRR (Status Report Request)
        tp_srr = bool(pdu_bytes[0] & 0x20)
        
        # Parse TP-MR (Message Reference)
        tp_mr = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-DA (Destination Address)
        tp_da, offset = self._parse_address(pdu_bytes, offset)
        
        # Parse TP-PID (Protocol Identifier)
        tp_pid = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-DCS (Data Coding Scheme)
        tp_dcs = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-VP (Validity Period) - variable length based on VPF
        if tp_vpf == 0:
            # No validity period
            pass
        elif tp_vpf == 1:
            # Relative format (observed)
            tp_vp_relative = pdu_bytes[offset]
            offset += 1
        elif tp_vpf == 2:
            # Relative format (common in the wild for bit pattern '10')
            tp_vp_relative = pdu_bytes[offset]
            offset += 1
        elif tp_vpf == 3:
            # Absolute format (timestamp)
            tp_vp_absolute, offset = self._parse_timestamp(pdu_bytes, offset)
        
        # Parse TP-UDL (User Data Length)
        tp_udl = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-UD (User Data)
        tp_ud = None
        tp_ud_hex = None
        if tp_udl > 0 and offset < len(pdu_bytes):
            is_7bit = (tp_dcs & 0x0C) == 0
            ud_octets = (tp_udl * 7 + 7)//8 if is_7bit else tp_udl
            ud_bytes = pdu_bytes[offset:offset + ud_octets]
            tp_ud_hex = ud_bytes.hex().upper()
            tp_ud = self._decode_user_data(ud_bytes, tp_dcs, tp_udl)
        
        return SMSMessage(
            pdu_type="SMS-SUBMIT",
            tp_mti=TPDU_MT_SMS_SUBMIT,
            tp_mr=tp_mr,
            tp_rd=tp_rd,
            tp_vpf=tp_vpf,
            tp_da=tp_da,
            tp_pid=tp_pid,
            tp_dcs=tp_dcs,
            tp_udl=tp_udl,
            tp_ud=tp_ud,
            tp_ud_hex=tp_ud_hex
        )
    
    def _parse_sms_status_report(self, pdu_bytes: bytes) -> SMSMessage:
        """Parse SMS-STATUS-REPORT TPDU (GSM 03.40 section 9.2.2.3)"""
        self.logger.debug("Parsing SMS-STATUS-REPORT")
        
        offset = 1  # Skip MTI byte
        
        # Parse TP-UDHI (User Data Header Indicator)
        tp_udhi = bool(pdu_bytes[0] & 0x40)
        
        # Parse TP-SRI (Status Report Indication)
        tp_sri = bool(pdu_bytes[0] & 0x20)
        
        offset += 1
        
        # Parse TP-MR (Message Reference)
        tp_mr = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-RA (Recipient Address)
        tp_ra, offset = self._parse_address(pdu_bytes, offset)
        
        # Parse TP-SCTS (Service Centre Time Stamp)
        tp_scts, offset = self._parse_timestamp(pdu_bytes, offset)
        
        # Parse TP-DT (Discharge Time)
        tp_dt, offset = self._parse_timestamp(pdu_bytes, offset)
        
        # Parse TP-ST (Status)
        tp_st = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-PI (Parameter Indicator)
        tp_pi = pdu_bytes[offset]
        offset += 1
        
        # Parse TP-PID (Protocol Identifier) if present
        tp_pid = None
        if tp_pi & 0x01:
            tp_pid = pdu_bytes[offset]
            offset += 1
        
        # Parse TP-DCS (Data Coding Scheme) if present
        tp_dcs = None
        if tp_pi & 0x02:
            tp_dcs = pdu_bytes[offset]
            offset += 1
        
        # Parse TP-UDL (User Data Length) if present
        tp_udl = None
        if tp_pi & 0x04:
            tp_udl = pdu_bytes[offset]
            offset += 1
        
        # Parse TP-UD (User Data) if present
        tp_ud = None
        tp_ud_hex = None
        if tp_udl and tp_udl > 0 and offset < len(pdu_bytes):
            is_7bit = ((tp_dcs or 0) & 0x0C) == 0
            ud_octets = (tp_udl * 7 + 7) // 8 if is_7bit else tp_udl
            ud_bytes = pdu_bytes[offset:offset + ud_octets]
            tp_ud_hex = ud_bytes.hex().upper()
            tp_ud = self._decode_user_data(ud_bytes, tp_dcs or 0, tp_udl)
        
        return SMSMessage(
            pdu_type="SMS-STATUS-REPORT",
            tp_mti=TPDU_MT_SMS_STATUS_REPORT,
            tp_mr=tp_mr,
            tp_ra=tp_ra,
            tp_scts=tp_scts,
            tp_dt=tp_dt,
            tp_st=tp_st,
            tp_pi=tp_pi,
            tp_pid=tp_pid,
            tp_dcs=tp_dcs,
            tp_udl=tp_udl,
            tp_ud=tp_ud,
            tp_ud_hex=tp_ud_hex
        )

    def _parse_sms_deliver_report(self, pdu_bytes: bytes) -> SMSMessage:
        """Parse SMS-DELIVER-REPORT TPDU (GSM 03.40 section 9.2.2.1a).

        Minimal parser: supports optional TP-FCS, TP-PI and optional TP-PID/TP-DCS/TP-UDL/TP-UD.
        Used when we receive RP-ACK carrying a DELIVER-REPORT from MS to SC.
        """
        self.logger.debug("Parsing SMS-DELIVER-REPORT")
        offset = 1  # Skip MTI/flags

        tp_fcs: Optional[int] = None
        tp_pi: Optional[int] = None
        tp_pid: Optional[int] = None
        tp_dcs: Optional[int] = None
        tp_udl: Optional[int] = None
        tp_ud: Optional[str] = None
        tp_ud_hex: Optional[str] = None

        remaining = len(pdu_bytes) - offset
        if remaining <= 0:
            return SMSMessage(
                pdu_type="SMS-DELIVER-REPORT",
                tp_mti=TPDU_MT_SMS_DELIVER_REPORT,
                tp_fcs=tp_fcs,
                tp_pi=tp_pi,
            )

        # Heuristic: if we have at least 2 octets, first can be FCS then PI.
        # If only 1 octet remains, treat it as PI (success case without FCS).
        if remaining >= 2:
            tp_fcs = pdu_bytes[offset]
            offset += 1
            tp_pi = pdu_bytes[offset]
            offset += 1
        else:
            tp_pi = pdu_bytes[offset]
            offset += 1

        if tp_pi is not None:
            if tp_pi & 0x01 and offset < len(pdu_bytes):
                tp_pid = pdu_bytes[offset]
                offset += 1
            if tp_pi & 0x02 and offset < len(pdu_bytes):
                tp_dcs = pdu_bytes[offset]
                offset += 1
            if tp_pi & 0x04 and offset < len(pdu_bytes):
                tp_udl = pdu_bytes[offset]
                offset += 1
                if tp_udl > 0 and offset < len(pdu_bytes):
                    is_7bit = ((tp_dcs or 0) & 0x0C) == 0
                    ud_octets = (tp_udl * 7 + 7) // 8 if is_7bit else tp_udl
                    ud_bytes = pdu_bytes[offset:offset + ud_octets]
                    tp_ud_hex = ud_bytes.hex().upper()
                    tp_ud = self._decode_user_data(ud_bytes, tp_dcs or 0, tp_udl)

        return SMSMessage(
            pdu_type="SMS-DELIVER-REPORT",
            tp_mti=TPDU_MT_SMS_DELIVER_REPORT,
            tp_fcs=tp_fcs,
            tp_pi=tp_pi,
            tp_pid=tp_pid,
            tp_dcs=tp_dcs,
            tp_udl=tp_udl,
            tp_ud=tp_ud,
            tp_ud_hex=tp_ud_hex,
        )

    def _parse_address(self, pdu_bytes: bytes, offset: int) -> Tuple[SMSAddress, int]:
        """Parse SMS address (TP-OA, TP-DA, TP-RA)"""
        if offset >= len(pdu_bytes):
            raise ValueError("PDU too short for address")
        
        # Address length
        addr_len = pdu_bytes[offset]
        offset += 1
        
        self.logger.debug(f"Address length (raw): {addr_len}")
        
        if addr_len == 0:
            return SMSAddress(ADDR_TYPE_UNKNOWN, ""), offset
        
        if offset >= len(pdu_bytes):
            raise ValueError("PDU too short for address type")
        
        # Type of address
        addr_type = pdu_bytes[offset]
        offset += 1
        
        self.logger.debug(f"Address type: 0x{addr_type:02X}")
        
        # Calculate number of address bytes to consume and how to decode them.
        # Numeric addresses use BCD semi-octets; length = number of digits.
        # Alphanumeric addresses (TOA=0xD0) are GSM 7-bit packed; the length field
        # encodes the number of useful semi-octets (n). Then:
        #   byte_len = ceil(n / 2)
        #   char_len = floor((n * 4) / 7)
        if addr_type == ADDR_TYPE_ALPHANUMERIC:
            semi_octet_len = addr_len
            byte_len = (semi_octet_len + 1) // 2
            char_len = (semi_octet_len * 4) // 7
            self.logger.debug(
                f"Alphanumeric address: semi_octets={semi_octet_len}, bytes={byte_len}, chars={char_len}"
            )
        else:
            digit_len = addr_len
            byte_len = (digit_len + 1) // 2  # two digits per octet (semi-octet swapped)
            self.logger.debug(f"Numeric address: digits={digit_len}, bytes={byte_len}")
        
        if offset + byte_len > len(pdu_bytes):
            raise ValueError(f"PDU too short for address data: need {byte_len} bytes, have {len(pdu_bytes) - offset}")
        
        # Extract address bytes
        addr_bytes = pdu_bytes[offset:offset + byte_len]
        offset += byte_len
        
        self.logger.debug(f"Address bytes: {addr_bytes.hex().upper()}")
        
        # Decode address
        if addr_type == ADDR_TYPE_ALPHANUMERIC:
            # Alphanumeric address (7-bit packed)
            number = self._decode_7bit_packed(addr_bytes, char_len)
            return SMSAddress(addr_type, number, is_alphanumeric=True), offset
        else:
            # Numeric address (BCD)
            number = self._decode_bcd(addr_bytes, digit_len)
            return SMSAddress(addr_type, number), offset
    
    # ---------------------------------------------------------------------
    # Helpers – Encoding
    # ---------------------------------------------------------------------
    def _encode_tp_address(self, number: str, addr_type: int) -> bytes:
        """Encode TP address field: [length][type][digits...].

        - number: numeric string, may start with '+' (ignored for digits)
        - addr_type: TOA value (0x91 international etc.)
        """
        digits = ''.join(ch for ch in number if ch.isdigit())
        digit_len = len(digits)
        # Build BCD with semi-octet swapped (low nibble first)
        nibbles = [int(d) for d in digits]
        if digit_len % 2 == 1:
            nibbles.append(0xF)
        bcd_bytes = bytearray()
        for i in range(0, len(nibbles), 2):
            low = nibbles[i] & 0x0F
            high = nibbles[i + 1] & 0x0F
            bcd_bytes.append((high << 4) | low)

        result = bytearray()
        result.append(digit_len & 0xFF)
        result.append(addr_type & 0xFF)
        result.extend(bcd_bytes)
        return bytes(result)

    def _encode_timestamp(self, dt_obj: datetime) -> bytes:
        """Encode GSM SCTS/DT timestamp (YY MM DD HH MM SS TZ) with swapped BCD.

        Timezone is encoded in quarters of an hour with sign bit at low-nibble bit 3.
        """
        # Ensure timezone-aware
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.astimezone()
        yy = dt_obj.year % 100
        mm = dt_obj.month
        dd = dt_obj.day
        hh = dt_obj.hour
        mi = dt_obj.minute
        ss = dt_obj.second

        def to_swapped_bcd(val: int) -> int:
            tens = (val // 10) % 10
            units = val % 10
            return ((units & 0x0F) << 4) | (tens & 0x0F)

        # Timezone in quarters of an hour
        offset = dt_obj.utcoffset() or timedelta(0)
        total_minutes = int(offset.total_seconds() // 60)
        negative = total_minutes < 0
        qh = abs(total_minutes) // 15
        tz_octet = ((qh // 10) << 4) | (qh % 10)
        if negative:
            tz_octet |= 0x08

        return bytes([
            to_swapped_bcd(yy),
            to_swapped_bcd(mm),
            to_swapped_bcd(dd),
            to_swapped_bcd(hh),
            to_swapped_bcd(mi),
            to_swapped_bcd(ss),
            tz_octet & 0xFF,
        ])

    def _encode_7bit(self, text: str) -> Tuple[bytes, int]:
        """Encode string using GSM 03.38 7-bit default alphabet.

        Returns (packed_bytes, septet_count).
        Unknown chars are replaced with '?'.
        """
        septets: list[int] = []
        for ch in text:
            code = self._gsm7_encode_map.get(ch)
            if code is None:
                code = self._gsm7_encode_map.get('?', 0x3F)
            septets.append(code & 0x7F)

        if not septets:
            return b"", 0

        total_bits = len(septets) * 7
        byte_len = (total_bits + 7) // 8
        out = bytearray(byte_len)

        bit_pos = 0
        for s in septets:
            byte_index = bit_pos // 8
            bit_in_byte = bit_pos % 8
            out[byte_index] |= (s << bit_in_byte) & 0xFF
            if bit_in_byte > 1:
                if byte_index + 1 < byte_len:
                    out[byte_index + 1] |= (s >> (8 - bit_in_byte)) & 0xFF
            bit_pos += 7

        return bytes(out), len(septets)
    def _parse_timestamp(self, pdu_bytes: bytes, offset: int) -> Tuple[SMSTimestamp, int]:
        """Parse SMS timestamp (TP-SCTS, TP-DT)"""
        if offset + 7 > len(pdu_bytes):
            raise ValueError("PDU too short for timestamp")
        
        # Timestamp is 7 bytes in BCD format: YYMMDDHHMMSSZ
        timestamp_bytes = pdu_bytes[offset:offset + 7]
        offset += 7
        
        self.logger.debug(f"Timestamp bytes: {timestamp_bytes.hex().upper()}")
        
        # Decode BCD values
        year = self._bcd_to_int(timestamp_bytes[0])
        month = self._bcd_to_int(timestamp_bytes[1])
        day = self._bcd_to_int(timestamp_bytes[2])
        hour = self._bcd_to_int(timestamp_bytes[3])
        minute = self._bcd_to_int(timestamp_bytes[4])
        second = self._bcd_to_int(timestamp_bytes[5])
        
        # Timezone offset (semi-octet swapped, with sign bit in low nibble bit 3)
        tz_octet = timestamp_bytes[6]
        sign_negative = (tz_octet & 0x08) != 0
        tz_quarter_hours = ((tz_octet & 0xF0) >> 4) * 10 + (tz_octet & 0x07)
        timezone_offset = tz_quarter_hours * 15  # Convert to minutes
        if sign_negative:
            timezone_offset = -timezone_offset

        self.logger.debug(
            f"Parsed timestamp: {year:02d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d} TZ(min):{timezone_offset}")
        
        # Validate timestamp values
        if not (1 <= month <= 12):
            self.logger.warning(f"Invalid month: {month}, using 1")
            month = 1
        if not (1 <= day <= 31):
            self.logger.warning(f"Invalid day: {day}, using 1")
            day = 1
        if not (0 <= hour <= 23):
            self.logger.warning(f"Invalid hour: {hour}, using 0")
            hour = 0
        if not (0 <= minute <= 59):
            self.logger.warning(f"Invalid minute: {minute}, using 0")
            minute = 0
        if not (0 <= second <= 59):
            self.logger.warning(f"Invalid second: {second}, using 0")
            second = 0
        
        return SMSTimestamp(year, month, day, hour, minute, second, timezone_offset), offset
    
    def _decode_user_data(self, ud_bytes: bytes, dcs: int, udl: int | None = None) -> str:
        """Decode user data based on data coding scheme.

        udl: User Data Length as encoded (septets for 7-bit, octets otherwise).
        """
        try:
            # Extract coding group
            coding_group = dcs & 0xF0
            
            if coding_group == 0x00:  # General data coding
                alphabet = dcs & 0x0C
                if alphabet == 0x00:  # 7-bit default alphabet
                    char_count = udl if udl is not None else (len(ud_bytes) * 8) // 7
                    return self._decode_7bit_packed(ud_bytes, char_count)
                elif alphabet == 0x04:  # 8-bit data
                    return ud_bytes.decode('latin1', errors='replace')
                elif alphabet == 0x08:  # UCS2
                    return ud_bytes.decode('utf-16be', errors='replace')
                else:
                    return f"<unsupported_alphabet_{alphabet}>"
            elif coding_group == 0xF0:  # Message Waiting Indication Group
                # Bit 0 indicates active status, bit 1 charset (0=7bit,1=UCS2)
                alphabet = (dcs & 0x02)
                if alphabet == 0x00:
                    char_count = udl if udl is not None else (len(ud_bytes) * 8) // 7
                    return self._decode_7bit_packed(ud_bytes, char_count)
                else:
                    return ud_bytes.decode('utf-16be', errors='replace')
            else:
                return f"<unsupported_coding_group_{coding_group}>"
                
        except Exception as e:
            self.logger.warning(f"Failed to decode user data: {e}")
            return f"<decode_error_{len(ud_bytes)}_bytes>"
    
    def _decode_7bit_packed(self, packed_bytes: bytes, char_count: int) -> str:
        """Decode 7-bit packed data (GSM 03.38)"""
        if not packed_bytes:
            return ""
        
        # GSM 7-bit default alphabet
        gsm_alphabet = (
            '@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !"#¤%&\'()*+,-./'
            '0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿'
            'abcdefghijklmnopqrstuvwxyzäöñüà'
        )
        
        # Unpack 7-bit data
        result: list[str] = []
        
        for i in range(char_count):
            bit_index = i * 7
            byte_index = bit_index // 8
            shift = bit_index % 8

            if byte_index >= len(packed_bytes):
                break

            # Extract 7 bits across one or two bytes
            current_byte = packed_bytes[byte_index]
            next_byte = packed_bytes[byte_index + 1] if (byte_index + 1) < len(packed_bytes) else 0

            char_code = ((current_byte >> shift) | (next_byte << (8 - shift))) & 0x7F
            
            # Map to GSM alphabet
            if char_code < len(gsm_alphabet):
                result.append(gsm_alphabet[char_code])
            else:
                result.append(f'<{char_code:02X}>')
          
        return ''.join(result)
    
    def _decode_bcd(self, bcd_bytes: bytes, digit_count: int) -> str:
        """Decode semi-octet swapped BCD digits (used for addresses)."""
        digits: list[str] = []
        consumed = 0
        for byte in bcd_bytes:
            if consumed >= digit_count:
                break
            low_digit = byte & 0x0F
            high_digit = (byte >> 4) & 0x0F
            # Low nibble first
            if low_digit != 0x0F and consumed < digit_count:
                digits.append(str(low_digit))
                consumed += 1
            if high_digit != 0x0F and consumed < digit_count:
                digits.append(str(high_digit))
                consumed += 1
        return ''.join(digits)

    def _swap_nibbles(self, byte: int) -> int:
        """Swap high and low nibbles in a byte"""
        return ((byte & 0x0F) << 4) | ((byte & 0xF0) >> 4)

    def _bcd_to_int(self, bcd_byte: int) -> int:
        """Convert semi-octet swapped BCD byte to integer.

        GSM 03.40 encodes digits with the least significant nibble first
        (i.e. the two decimal digits within a byte are swapped compared
        to normal BCD). Example: byte 0x52 represents digits "25".
        """
        low = bcd_byte & 0x0F   # units
        high = (bcd_byte >> 4) & 0x0F  # tens
        return low * 10 + high

# Convenience wrappers

def decode_gsm_sms_pdu(hex_pdu: str) -> SMSMessage:
    """Convenience function to decode GSM SMS PDU"""
    parser = GSMSMSAPDU()
    return parser.decode_pdu(hex_pdu)

def encode_gsm_sms_deliver(
    tp_oa_number: str,
    text: str,
    *,
    pid: int = 0x00,
    dcs: int = 0x00,
    scts_dt: Optional[datetime] = None,
    toa: int = ADDR_TYPE_INTERNATIONAL,
    flags_octet0: int = 0x24,
) -> str:
    """Convenience to build SMS-DELIVER TPDU and return hex string."""
    parser = GSMSMSAPDU()
    tpdu = parser.encode_sms_deliver(
        originating_address=tp_oa_number,
        user_data_text=text,
        pid=pid,
        dcs=dcs,
        scts_dt=scts_dt,
        originating_addr_type=toa,
        deliver_flags_octet0=flags_octet0,
    )
    return tpdu.hex().upper()

if __name__ == "__main__":
    # Test the parser
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python gsm_sms_apdu.py <hex_pdu>")
        sys.exit(1)
    
    hex_pdu = sys.argv[1]
    
    try:
        sms = decode_gsm_sms_pdu(hex_pdu)
        print(f"PDU TYPE: {sms.pdu_type}")
        
        if sms.tp_oa:
            print(f"FROM: {sms.tp_oa}")
        
        if sms.tp_da:
            print(f"TO: {sms.tp_da}")
        
        if sms.tp_scts:
            print(f"TIMESTAMP: {sms.tp_scts}")
        
        if sms.tp_ud:
            print(f"TEXT: {sms.tp_ud}")
        
        if sms.tp_ud_hex:
            print(f"RAW DATA: {sms.tp_ud_hex}")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1) 
