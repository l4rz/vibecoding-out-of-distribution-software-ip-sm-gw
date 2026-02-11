#!/usr/bin/env python3
"""
GSM SMS TPDU (SMS-SUBMIT/SMS-DELIVER) Decode Test Script
========================

Simple test script that takes raw hex APDUs from the command line and prints the decoded SMS fields.
"""

import sys
import logging
from gsm_sms_apdu import decode_gsm_sms_pdu, SMSMessage

def print_sms_details(sms: SMSMessage):
    """Print detailed SMS information"""
    print("=" * 60)
    print(f"PDU TYPE: {sms.pdu_type}")
    print("=" * 60)
    
    # Basic fields
    if sms.tp_mr is not None:
        print(f"Message Reference: {sms.tp_mr}")
    
    if sms.tp_oa:
        print(f"FROM: {sms.tp_oa}")
    
    if sms.tp_da:
        print(f"TO: {sms.tp_da}")
    
    if hasattr(sms, 'tp_ra') and sms.tp_ra:
        print(f"RECIPIENT: {sms.tp_ra}")
    
    if sms.tp_scts:
        print(f"TIMESTAMP: {sms.tp_scts}")
    
    if sms.tp_dt:
        print(f"DISCHARGE TIME: {sms.tp_dt}")
    
    if sms.tp_ud:
        print(f"TEXT: {sms.tp_ud}")
    
    # Protocol details
    if sms.tp_pid is not None:
        print(f"Protocol ID: 0x{sms.tp_pid:02X}")
    
    if sms.tp_dcs is not None:
        print(f"Data Coding Scheme: 0x{sms.tp_dcs:02X}")
    
    if sms.tp_udl is not None:
        print(f"User Data Length: {sms.tp_udl}")
    
    if sms.tp_st is not None:
        print(f"Status: 0x{sms.tp_st:02X}")
    
    # SMS-DELIVER specific fields
    if sms.tp_mms is not None:
        print(f"More Messages: {sms.tp_mms}")
    
    if sms.tp_lp is not None:
        print(f"Loop Prevention: {sms.tp_lp}")
    
    # SMS-SUBMIT specific fields
    if sms.tp_rd is not None:
        print(f"Reject Duplicates: {sms.tp_rd}")
    
    if sms.tp_vpf is not None:
        print(f"Validity Period Format: {sms.tp_vpf}")
    
    if sms.tp_srr is not None:
        print(f"Status Report Request: {sms.tp_srr}")
    
    # Raw data
    if sms.tp_ud_hex:
        print(f"RAW DATA: {sms.tp_ud_hex}")
    
    print()

def main():
    """Main test function"""
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python gsm_sms_apdu_test.py <hex_pdu1> [hex_pdu2] ...")
        print()
        sys.exit(1)
    
    # Process each PDU
    for i, hex_pdu in enumerate(sys.argv[1:], 1):
        print(f"Testing PDU #{i}: {hex_pdu}")
        print(f"Length: {len(hex_pdu)} hex chars ({len(hex_pdu)//2} bytes)")
        
        try:
            sms = decode_gsm_sms_pdu(hex_pdu)
            print_sms_details(sms)
        except Exception as e:
            print(f"ERROR: Failed to decode PDU: {e}")
            print()
            continue

if __name__ == "__main__":
    main() 
