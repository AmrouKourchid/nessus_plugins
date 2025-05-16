#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213556);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2025-21602");
  script_xref(name:"JSA", value:"JSA92872");
  script_xref(name:"IAVA", value:"2025-A-0018");

  script_name(english:"Juniper Junos OS Vulnerability (JSA92872)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA92872
advisory.

  - An Improper Handling of Exceptional Conditions vulnerability in the routing protocol daemon (rpd) of
    Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated adjacent attacker sending a
    specific BGP update packet to cause rpd to crash and restart, resulting in a Denial of Service (DoS).
    Continuous receipt and processing of this packet will create a sustained Denial of Service (DoS)
    condition. This issue affects iBGP and eBGP, and both IPv4 and IPv6 are affected by this vulnerability.
    This issue affects Junos OS: * from 21.4 before 21.4R3-S9, * from 22.2 before 22.2R3-S5, * from 22.3
    before 22.3R3-S4, * from 22.4 before 22.4R3-S5, * from 23.2 before 23.2R2-S3, * from 23.4 before
    23.4R2-S3, * from 24.2 before 24.2R1-S2, 24.2R2; This issue does not affect versions prior to 21.1R1.
    Junos OS Evolved: * from 21.4 before 21.4R3-S9-EVO, * from 22.2 before 22.2R3-S5-EVO, * from 22.3 before
    22.3R3-S4-EVO, * from 22.4 before 22.4R3-S5-EVO, * from 23.2 before 23.2R2-S3-EVO, * from 23.4 before
    23.4R2-S3-EVO, * from 24.2 before 24.2R1-S2-EVO, 24.2R2-EVO. This issue does not affect versions prior to
    21.1R1-EVO (CVE-2025-21602)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2025-01-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Receipt-of-specially-crafted-BGP-update-packet-causes-RPD-crash-CVE-2025-21602
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58034766");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA92872");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/AU:N/R:A/V:C/RE:M/U:Green");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21602");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S9'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S9'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S5'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S4'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S5'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2-S3'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R2-S3'},
  {'min_ver':'24.2', 'fixed_ver':'24.2R1-S2', 'fixed_display':'24.2R1-S2, 24.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
