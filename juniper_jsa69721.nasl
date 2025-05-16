#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178644);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2022-22217");
  script_xref(name:"JSA", value:"JSA69721");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69721)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69721
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in the Packet Forwarding Engine
    (PFE) of Juniper Networks Junos OS allows an adjacent unauthenticated attacker to cause a Denial of
    Service (DoS). The issue is caused by malformed MLD packets looping on a multi-homed Ethernet Segment
    Identifier (ESI) when VXLAN is configured. These MLD packets received on a multi-homed ESI are sent to the
    peer, and then incorrectly forwarded out the same ESI, violating the split horizon rule. This issue only
    affects QFX10K Series switches, including the QFX10002, QFX10008, and QFX10016. Other products and
    platforms are unaffected by this vulnerability. This issue affects Juniper Networks Junos OS on QFX10K
    Series: All versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R1-S9, 19.2R3-S5; 19.3 versions prior
    to 19.3R3-S6; 19.4 versions prior to 19.4R2-S7, 19.4R3-S8; 20.1 versions prior to 20.1R3-S4; 20.2 versions
    prior to 20.2R3-S4; 20.3 versions prior to 20.3R3-S2; 20.4 versions prior to 20.4R3-S2; 21.1 versions
    prior to 21.1R3; 21.2 versions prior to 21.2R2-S1, 21.2R3; 21.3 versions prior to 21.3R2. (CVE-2022-22217)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2022-07-Security-Bulletin-Junos-OS-QFX10k-Series-Denial-of-Service-DoS-upon-receipt-of-crafted-MLD-packets-on-multi-homing-ESI-in-VXLAN-CVE-2022-22217
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dd6011c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69721");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^QFX1")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'19.1R3-S9', 'model':'^QFX1'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S9', 'model':'^QFX1'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S5', 'model':'^QFX1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S6', 'model':'^QFX1'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S7', 'model':'^QFX1'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S8', 'model':'^QFX1'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S4', 'model':'^QFX1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S4', 'model':'^QFX1'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2', 'model':'^QFX1'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S2', 'model':'^QFX1'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3', 'model':'^QFX1'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2-S1', 'model':'^QFX1', 'fixed_display':'21.2R2-S1, 21.2R3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2', 'model':'^QFX1'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
