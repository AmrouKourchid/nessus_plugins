#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208679);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2024-47502");
  script_xref(name:"JSA", value:"JSA88132");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS Vulnerability (JSA88132)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88132
advisory.

  - An Allocation of Resources Without Limits or Throttling vulnerability in the kernel of Juniper Networks
    Junos OS Evolved allows an unauthenticated, network based attacker to cause a Denial of Service (DoS).
    (CVE-2024-47502)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-Evolved-TCP-session-state-is-not-always-cleared-on-the-Routing-Engine-CVE-2024-47502
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2d41865");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88132");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/AU:Y/R:U/RE:M");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47502");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.4R3-S9-EVO'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S4-EVO'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-S3-EVO'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R2-S1-EVO'},
  {'min_ver':'23.4-EVO', 'fixed_ver':'23.4R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
