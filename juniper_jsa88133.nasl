#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208475);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2024-47503");
  script_xref(name:"JSA", value:"JSA88133");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS Vulnerability (JSA88133)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88133
advisory.

  - An Improper Check for Unusual or Exceptional Conditions vulnerability in the flow processing daemon
    (flowd) of Juniper Networks Junos OS on SRX4600 and SRX5000 Series allows an unauthenticated and logically
    adjacent attacker to cause a Denial-of-Service (DoS). (CVE-2024-47503)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-SRX4600-and-SRX5000-Series-Sequence-of-specific-PIM-packets-causes-a-flowd-crash-CVE-2024-47503
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6fa677d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88133");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(4600|5000|S|SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.4R3-S9', 'model':'^(4600|5000|S|SRX)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S5', 'model':'^(4600|5000|S|SRX)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S4', 'model':'^(4600|5000|S|SRX)'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S4', 'model':'^(4600|5000|S|SRX)'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2-S2', 'model':'^(4600|5000|S|SRX)'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R2', 'model':'^(4600|5000|S|SRX)'},
  {'min_ver':'24.2', 'fixed_ver':'24.2R1-S1', 'model':'^(4600|5000|S|SRX)', 'fixed_display':'24.2R1-S1, 24.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
