#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169940);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2023-22401");
  script_xref(name:"JSA", value:"JSA70197");
  script_xref(name:"IAVA", value:"2023-A-0041");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70197)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70197
advisory.

  - An Improper Validation of Array Index vulnerability in the Advanced Forwarding Toolkit Manager daemon
    (aftmand) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated, network-based
    attacker to cause a Denial of Service (DoS). (CVE-2023-22401)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-01-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-PTX10008-PTX10016-When-a-specific-SNMP-MIB-is-queried-the-FPC-will-crash-CVE-2023-22401
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2caa2ce");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70197");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22401");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-EVO'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R1-S2-EVO', 'fixed_display':'21.4R1-S2-EVO, 21.4R2-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2', 'fixed_display':'22.1R2, 22.1R3'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R2-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R1-S1-EVO', 'fixed_display':'22.2R1-S1-EVO, 22.2R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
