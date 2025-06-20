#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151627);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2021-0295");
  script_xref(name:"JSA", value:"JSA11208");
  script_xref(name:"IAVA", value:"2021-A-0324-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11208)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11208
advisory.

  - A vulnerability in the Distance Vector Multicast Routing Protocol (DVMRP) of Juniper Networks Junos OS on
    the QFX10K Series switches allows an attacker to trigger a packet forwarding loop, leading to a partial
    Denial of Service (DoS). The issue is caused by DVMRP packets looping on a multi-homed Ethernet Segment
    Identifier (ESI) when VXLAN is configured. DVMRP packets received on a multi-homed ESI are sent to the
    peer, and then incorrectly forwarded out the same ESI, violating the split horizon rule. (CVE-2021-0295)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2021-07-Security-Bulletin-Junos-OS-QFX10K-Series-Denial-of-Service-DoS-upon-receipt-of-DVMRP-packets-received-on-multi-homing-ESI-in-VXLAN-CVE-2021-0295
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b20292b");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11208");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0295");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S12', 'model':'^QFX1'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R3-S5', 'model':'^QFX1'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13', 'model':'^QFX1'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R1', 'model':'^QFX1'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5', 'model':'^QFX1'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S9', 'model':'^QFX1'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S8', 'model':'^QFX1'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5', 'model':'^QFX1'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7', 'model':'^QFX1'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S2', 'model':'^QFX1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S2', 'model':'^QFX1'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S3', 'model':'^QFX1'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2', 'model':'^QFX1', 'fixed_display':'20.1R2-S2, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3', 'model':'^QFX1'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3', 'model':'^QFX1'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2', 'model':'^QFX1'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
