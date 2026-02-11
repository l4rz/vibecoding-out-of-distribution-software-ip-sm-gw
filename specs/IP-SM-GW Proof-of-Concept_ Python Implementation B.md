<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# IP-SM-GW Proof-of-Concept: Python Implementation Blueprint

The following specification gives an AI coding assistant everything it needs to scaffold a working IP-SM-GW prototype that fulfils ETSI TS 124 341 V17.1.0 requirements for REGISTER and MESSAGE handling. It covers call flows, precise SIP/Diameter processing logic, recommended Python libraries, data structures, and unit-test hooks.

One-sentence summary: **Build a lightweight SIP AS that converts IMS SMS (vnd.3gpp.sms) into plain SIP toward an SMS hub while performing third-party registration and HSS interrogation via python-diameter, entirely in Python for 1 TPS lab-scale traffic.**

## 1. High-Level Architecture

The PoC node sits as a SIP Application Server behind the home S-CSCF and in front of the legacy SMS hub (EMG). External interfaces are:

- ISC (SIP) toward S-CSCF
- Diameter S6c / MAP J or SRI-SM over python-diameter toward HSS (for simplicity, implement S6c Credit-Control style queries)
- Optional E/Gd MAP toward SMS-GMSC/ IWMSC is out-of-scope in this phase.

![Figure 1 – IP-SM-GW PoC architecture and external interfaces](https://user-gen-media-assets.s3.amazonaws.com/gpt4o_images/509f13c1-94ac-4385-be8f-c675d2c613e4.png)

Figure 1 – IP-SM-GW PoC architecture and external interfaces

### Component Micro-services

| Module | Responsibility | Tech choice |
| :-- | :-- | :-- |
| `sip_frontend.py` | Stateless asyncio SIP UDP/TCP listener, REGISTER \& MESSAGE parser, high-availability dispatcher | [`aiosip`](https://github.com/eyepea/aiosip) or [`pysip`](https://pypi.org/project/pyVoIP/) |
| `sms_codec.py` | Encode/decode 3GPP RP-DATA / RP-ACK inside `application/vnd.3gpp.sms` | [`smspdu`](https://pypi.org/project/smspdu/) or `smspdudecoder` |
| `diameter_client.py` | Minimal Diameter node (CER/DWR) plus custom S6c‐SendRoutingInfoForSM request | `python-diameter` |
| `registry.py` | Maintains IMSI ↔ Public ID ↔ MSISDN cache, driven by third-party REGISTER events | Redis (optional) |
| `router.py` | Domain selection logic (IMS only → route to EMG) | pure Python |

## 2. Flows Decomposed from TS 24 341 §5.3.3

### 2.1 Third-Party REGISTER Handling

#### Trigger

- Home S-CSCF detects `+g.3gpp.smsip` in UE REGISTER contact; fires third-party REGISTER to IP-SM-GW per §5.3.3.2.


#### PoC processing steps

1. Parse XML body (`Content-Type: application/3gpp-ims+xml`) and extract:
    * IMSI (from `<private-id>` or Authorization header)
    * Public RID/TEL URI
    * Contact‐Expires timer
2. Store binding `REG_DB[IMSI] = tel_uri , expiry`.
3. Build Diameter S6c `PUR`/`PUA` (or MAP ATI) to update HSS subscriber data:
    * AVP `SMS-Registration-Info` → Available.
4. Send 200 OK to S-CSCF.
5. Subscribe to REG event package (RFC 3680) for status changes (not mandatory in PoC, can be TODO).

![Figure 2 – Simplified REGISTER and MO-SMS signalling flows in the PoC](https://user-gen-media-assets.s3.amazonaws.com/gpt4o_images/5035907b-0e2b-4528-9a38-a0b762cbdf92.png)

Figure 2 – Simplified REGISTER and MO-SMS signalling flows in the PoC

### 2.2 Mobile-Originated MESSAGE Handling

1. Receive `SIP MESSAGE` with `Content-Type: application/vnd.3gpp.sms`.
2. Use `sms_codec.decode()` to obtain RP-DATA PDU.
3. Validate sender MSISDN from `P-Asserted-Identity` against registry; derive IMSI if needed.
4. Optionally query HSS (SRI-SM) to retrieve SC address or verify barring status.
5. Re-encode payload as **plain text SIP MESSAGE** toward EMG:
    * `Content-Type: text/plain`
    * Body: SMS TP-UDL text converted via GSM 7-bit or UCS2.
6. Log correlation ID (`Call-ID`) to map EMG submit reports back (future work).
7. Return `202 Accepted` to S-CSCF.

## 3. Detailed API Contracts

### 3.1 `sms_codec.py`

```python
from smspdu import RP_DATA, SMS_SUBMIT, SMS_DELIVER

def decode_vnd_sms(binary_body: bytes) -> dict:
    """Return dict with keys tp_oa, tp_da, user_data (str), rp_mti"""
    rp = RP_DATA.fromPDU(binary_body)
    sms = SMS_SUBMIT.fromPDU(rp.user_data, rp.rp_originator_address)
    return {
        "from": sms.tp_oa,
        "to": sms.tp_da,
        "text": sms.user_data,
        "ref": rp.rp_message_reference
    }
```


### 3.2 `diameter_client.py` skeleton

```python
from diameter.node import Node
from diameter.node.application import SimpleThreadingApplication
from diameter.message import Message
from diameter.message.constants import *

class S6cApp(SimpleThreadingApplication):
    def build_sri_sm(self, imsi:str) -> Message:
        msg = Message.new_request(8388620)  # experimental SRI-SM code
        msg.Session_Id = f"ipsmgw;{imsi}"
        msg.User_Name = imsi
        return msg
```


## 4. Library Selection Rationale

| Function | Library | Reason |
| :-- | :-- | :-- |
| SIP stack | **aiosip** (asyncio) – RFC3261 compliant; easy coroutine-based state machines | Non-blocking; Python ≥3.8 |
| Diameter | **python-diameter** by Mensonen | Active, SCTP/TCP, application templates |
| SMS PDU | **smspdu** or **smspdudecoder** | Parses RP-layer and TPDU easily |
| Testing | `pytest`, `asynctest`, `pytest-trio` | Async test harness |

## 5. Threading \& Performance

- Use asyncio event loop; single worker is enough for 1 msg/s.
- Diameter client runs in background task; keep-alive every 30 s (DWR/CEA).
- SIP transaction context stored in dict keyed by `Call-ID`.
- Graceful shutdown: send DPR to HSS, unregister from S-CSCF.


## 6. Configuration File (`config.yaml`)

```yaml
sip:
  bind: 0.0.0.0
  port: 5060
  home_domain: ims.mnc001.mcc001.3gppnetwork.org
  scscf_uri: sip:scscf1.ims.mnc001.mcc001.3gppnetwork.org
  emg_uri: sip:sms-hub.example.com

diameter:
  origin_host: ipsmgw.ims.mnc001.mcc001.3gppnetwork.org
  origin_realm: ims.mnc001.mcc001.3gppnetwork.org
  peer: hss.ims.mnc001.mcc001.3gppnetwork.org
  applications:
    - id: 16777251   # S6c
      vendor: 10415  # 3GPP
```


## 7. Unit-Test Checklist

| Test ID | Description | Expected |
| :-- | :-- | :-- |
| REG-001 | Third-party REGISTER parsed → cache populated | `registry.get(imsi)` returns TEL URI |
| REG-002 | Diameter PUR sent with AVP `SMS-Registration-Info=”AVAILABLE”` | HSS mock receives correct AVP layout |
| MSG-001 | MO SIP MESSAGE decoded → text matches “hello” | Assert routing to EMG with plain body “hello” |
| MSG-002 | Unknown Content-Type returns 415 | S-CSCF gets 415 Unsupported Media |

## 8. Future Extensions

1. **MT-SMS** (deliver to UE) implementing §5.3.3.4.2 and 24.204 domain selection.
2. **MAP over SIGTRAN** wrapper using `python-asn1` for legacy interop.
3. Cassandra store for correlation identifiers (IMSI + SRI-SM ref).
4. MSISDN-less subscription support per §5.3.3.5.

## 9. References (inline)

All procedures referenced are mapped to the following normative sources:

* ETSI TS 124 341 V17.1.0 clauses 4-5[^1_1]
* 3GPP TS 23.204 §5.3.1[^1_2]
* 3GPP TS 29.336 §4 (HSS AVPs)[^1_3]
* 3GPP TS 29.002 §12 SMS MAP operations[^1_4]
* RFC 3261, 3680 (SIP/Reg events) and RFC 3428 (IM)


## 10. Deliverables for AI Code Generator

1. `requirements.txt` with pinned versions of chosen libraries.
2. Four Python modules (`sip_frontend.py`, `sms_codec.py`, `diameter_client.py`, `router.py`), plus `main.py` loader wiring asyncio tasks.
3. `docker-compose.yml` including Redis and optional HSS stub.
4. `tests/` folder with pytest cases above.

The outline above is sufficient for an AI coding model to generate compile-ready code scaffolding, integration tests, and minimal runtime configuration.

<div style="text-align: center">⁂</div>

[^1_1]: https://www.etsi.org/deliver/etsi_ts/124300_124399/124341/17.01.00_60/ts_124341v170100p.pdf

[^1_2]: https://www.arib.or.jp/english/html/overview/doc/STD-T63v9_50/5_Appendix/R99/29/29002-3k0.pdf

[^1_3]: https://itecspec.com/spec/3gpp-29-002-12-short-message-service-management-services/

[^1_4]: https://baike.c114.com.cn/searchword.asp?s=11\&word=GMSC

[^1_5]: http://www.arib.or.jp/english/html/overview/doc/STD-T63v10_20/5_Appendix/Rel8/29/29311-830.pdf

[^1_6]: https://www.etsi.org/deliver/etsi_ts/124300_124399/124341/12.05.00_60/ts_124341v120500p.pdf

[^1_7]: https://www.pharos-corp.com/prod_ip_sm_gateway.html

[^1_8]: https://www.etsi.org/deliver/etsi_ts/123200_123299/123204/15.00.00_60/ts_123204v150000p.pdf

[^1_9]: https://cdn.standards.iteh.ai/samples/44287/8b2f795f0ffb4efcbc9076bd91615f3d/ETSI-TS-124-341-V11-3-0-2014-07-.pdf

[^1_10]: https://www.arib.or.jp/english/html/overview/doc/STD-T63v9_00/5_Appendix/Rel7/23/23204-760.pdf

[^1_11]: https://www.etsi.org/deliver/etsi_ts/123200_123299/123204/07.06.00_60/ts_123204v070600p.pdf

[^1_12]: https://cdn.standards.iteh.ai/samples/70595/2ed8c7f1cf534efa8527bd35b9867357/ETSI-TS-124-341-V18-0-0-2024-05-.pdf

[^1_13]: https://docs.rhino.metaswitch.com/ocdoc/books/sentinel-ipsmgw/2.8.0/ipsmgw-architecture-guide/index.html

[^1_14]: http://www.ttc.or.jp/st/docs/3gpps2013/TS/TS-3GA-29.311(Rel11)v11.1.0.pdf

[^1_15]: https://www.etsi.org/deliver/etsi_ts/124300_124399/124341/11.02.00_60/ts_124341v110200p.pdf

[^1_16]: https://docs.rhino.metaswitch.com/ocdoc/books/sentinel-ipsmgw/2.7.0/ipsmgw-architecture-guide/index-full.html

[^1_17]: http://www.arib.or.jp/english/html/overview/doc/STD-T63v10_50/5_Appendix/Rel10/24/24341-a10.pdf

[^1_18]: https://www.etsi.org/deliver/etsi_ts/124300_124399/124341/08.03.00_60/ts_124341v080300p.pdf

[^1_19]: https://www.3gpp.org/DynaReport/23824.htm

[^1_20]: https://www.etsi.org/deliver/etsi_ts/124300_124399/124341/15.02.00_60/ts_124341v150200p.pdf

[^1_21]: https://opencode.com/ip-sm-gateway

[^1_22]: https://www.3gpp.org/DynaReport/WiCr--32081.htm

[^1_23]: https://www.etsi.org/deliver/etsi_ts/124300_124399/124341/12.07.00_60/ts_124341v120700p.pdf

[^1_24]: https://pypi.org/project/sip/

[^1_25]: https://blog.51cto.com/u_16213329/12077664

[^1_26]: https://codepal.ai/code-generator/query/skl3YBN6/python-code-generates-sip-trying-message

[^1_27]: https://github.com/NicklasXYZ/pysip

[^1_28]: https://spack.readthedocs.io/en/v0.21.2/build_systems/sippackage.html

[^1_29]: https://python-sip.readthedocs.io/en/stable/introduction.html

[^1_30]: https://blog.51cto.com/u_16213317/12797324

[^1_31]: https://github.com/spacinov/sipmessage

[^1_32]: https://kandi.openweaver.com/python/SIPp/pysipp

[^1_33]: https://spack.readthedocs.io/en/v0.20.0/build_systems/sippackage.html

[^1_34]: https://pypi.org/project/pyVoIP/

[^1_35]: https://blog.51cto.com/u_16213400/13247302

[^1_36]: https://blog.51cto.com/u_16213441/10748249

[^1_37]: https://pypi.org/project/pysipp/

[^1_38]: https://python-sip.readthedocs.io/en/latest/examples.html

[^1_39]: https://github.com/AGProjects/python3-sipsimple

[^1_40]: https://blog.51cto.com/u_16213345/12009656

[^1_41]: https://pypi.org/project/sipmessage/

[^1_42]: https://pypi.org/project/pysip/

[^1_43]: https://github.com/gergelypeli/siplib

[^1_44]: https://www.etsi.org/deliver/etsi_ts/124300_124399/124341/09.01.00_60/ts_124341v090100p.pdf

[^1_45]: https://snyk.io/advisor/python/smspdu/example

[^1_46]: https://pkg.go.dev/github.com/voutilad/rp-connect-python

[^1_47]: https://gist.github.com/underdoeg/1262332

[^1_48]: https://stackoverflow.com/questions/20542043/what-sip-header-decides-that-a-sip-message-should-be-treated-as-an-sms

[^1_49]: https://github.com/pmarti/python-messaging/blob/master/messaging/sms/deliver.py

[^1_50]: https://github.com/voutilad/rp-connect-python

[^1_51]: https://null-byte.wonderhowto.com/how-to/send-sms-messages-with-python-0132938/

[^1_52]: https://pypi.org/project/smspdudecoder/

[^1_53]: https://github.com/gecko-landmarks/smspdu/blob/master/smspdu/pdu.py

[^1_54]: https://forums.raspberrypi.com/viewtopic.php?t=340232

[^1_55]: https://ozeki-sms-gateway.com/p_685-how-to-send-sms-from-python.html

[^1_56]: https://pypi.org/project/pdusms/

[^1_57]: https://cgit.osmocom.org/pysim/tree/pySim/sms.py?id=a3962b2076d157e075262c51e6c4d0a48ba12465

[^1_58]: https://stackoverflow.com/questions/59159168/python-parse-semi-structured-text-and-extract-to-structed-data

[^1_59]: https://www.callr.com/en/blog/sms-delivery-notification-system

[^1_60]: https://pypi.org/project/pdusmsconverter/

[^1_61]: https://stackoverflow.com/questions/40153861/python-smspdu-outputs-invalid-pdu-format

[^1_62]: https://github.com/soeaver/RP-R-CNN

[^1_63]: https://www.smsmode.com/en/sms-python-integration-envoi-sms-python/

[^1_64]: https://mensonen.github.io/diameter/guide/message/

[^1_65]: https://mensonen.github.io/diameter/

[^1_66]: https://pypi.org/project/python-diameter/

[^1_67]: https://mensonen.github.io/diameter/guide/application/

[^1_68]: https://github.com/yongs2/pydiameter

[^1_69]: https://manpages.debian.org/bookworm/erlang-manpages/diameter.3erl.en.html

[^1_70]: https://github.com/mensonen/diameter

[^1_71]: https://github.com/KellyKinyama

[^1_72]: https://erlang.org/documentation/doc-15.0/lib/diameter-2.4/doc/html/diameter_intro.html

[^1_73]: https://github.com/mensonen

[^1_74]: https://mensonen.github.io/diameter/setup/

[^1_75]: https://www.telecomhall.net/t/bromelia-python-micro-framework-for-building-diameter-protocol-applications/13799

[^1_76]: https://github.com/sandu-alexandru/asn_diameter_python

[^1_77]: https://github.com/topics/diameter?o=desc\&s=

[^1_78]: https://github.com/heimiricmr/bromelia

[^1_79]: http://i1.dk/PythonDiameter/

[^1_80]: https://github.com/topics/rfc6733

[^1_81]: https://infocenter.nokia.com/public/7750SR227R1A/topic/com.nokia.Triple_Play_Service_Delivery_Architecture_Guide/python_policy_n-ai9jxkma6k.html

[^1_82]: https://pypi.org/project/pyDiameter/

[^1_83]: https://github.com/yongs2/pydiameter/blob/master/diameter_client.py

[^1_84]: https://en.wikipedia.org/wiki/Short_Message_Service_technical_realisation_(GSM)

[^1_85]: https://www.3gpp.org/ftp/tsg_sa/tsg_sa/tsgs_28/docs/pdf/SP-050349.pdf

[^1_86]: https://www.arib.or.jp/english/html/overview/doc/STD-T63v11_30/5_Appendix/Rel12/29/29011-c00.pdf

[^1_87]: https://www.wikiwand.com/en/articles/Short_Message_Service_technical_realisation_(GSM)

[^1_88]: https://book.crifan.org/books/multimedia_core_system_ims/website/ims_element/related/ip_sm_gw.html

[^1_89]: https://www.arib.or.jp/english/html/overview/doc/STD-T63V9_21/5_Appendix/Rel10/29/29120-a00.pdf

[^1_90]: https://www.etsi.org/deliver/etsi_ts/129300_129399/129336/11.03.00_60/ts_129336v110300p.pdf

[^1_91]: https://www.etsi.org/deliver/etsi_ts/129000_129099/129002/05.06.01_60/ts_129002v050601p.pdf

[^1_92]: https://blog.csdn.net/yigeshouyiren/article/details/20212451

[^1_93]: https://www.arib.or.jp/english/html/overview/doc/STD-T63V12_00/5_Appendix/Rel13/23/23204-d00.pdf

[^1_94]: https://www.tech-invite.com/3m23/toc/tinv-3gpp-23-204_b.html

[^1_95]: https://www.mobius-software.com/documentation/Mobius+GMLC+Gateway/SS7+MAP

[^1_96]: https://www.etsi.org/deliver/etsi_TS/129300_129399/129338/16.02.00_60/ts_129338v160200p.pdf

[^1_97]: https://www.3gpp.org/dynareport/29002.htm

