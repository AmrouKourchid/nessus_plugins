#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234088);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2025-30645");
  script_xref(name:"JSA", value:"JSA96455");
  script_xref(name:"IAVA", value:"2025-A-0261");

  script_name(english:"Juniper Junos OS Vulnerability (JSA96455)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA96455
advisory.

  - A NULL Pointer Dereference vulnerability in the flow daemon (flowd) of Juniper Networks Junos OS on SRX
    Series allows an attacker causing specific, valid control traffic to be sent out of a Dual-Stack (DS) Lite
    tunnel to crash the flowd process, resulting in a Denial of Service (DoS). Continuous triggering of
    specific control traffic will create a sustained Denial of Service (DoS) condition. On all SRX platforms,
    when specific, valid control traffic needs to be sent out of a DS-Lite tunnel, a segmentation fault occurs
    within the flowd process, resulting in a network outage until the flowd process restarts. This issue
    affects Junos OS on SRX Series: * All versions before 21.2R3-S9, * from 21.4 before 21.4R3-S9, * from 22.2
    before 22.2R3-S5, * from 22.4 before 22.4R3-S6, * from 23.2 before 23.2R2-S3, * from 23.4 before 23.4R2.
    (CVE-2025-30645)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2025-04-Security-Bulletin-Junos-OS-SRX-Series-Transmission-of-specific-control-traffic-sent-out-of-a-DS-Lite-tunnel-results-in-flowd-crash-CVE-2025-30645
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d6f340d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA96455");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/AU:Y/R:A/V:C/RE:M/U:Green");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^SRX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.2R3-S9', 'model':'^SRX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S9', 'model':'^SRX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S5', 'model':'^SRX'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S6', 'model':'^SRX'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2-S3', 'model':'^SRX'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R2', 'model':'^SRX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
