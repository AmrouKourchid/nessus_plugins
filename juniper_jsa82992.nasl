#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202145);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id("CVE-2024-39532");
  script_xref(name:"JSA", value:"JSA82992");
  script_xref(name:"IAVA", value:"2024-A-0385");

  script_name(english:"Juniper Junos OS Vulnerability (JSA82992)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA82992
advisory.

  - An Insertion of Sensitive Information into Log File vulnerability in Juniper Networks Junos OS and Junos
    OS Evolved allows a local, authenticated attacker with high privileges to access sensitive information.
    (CVE-2024-39532)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2024-39532");
  # https://supportportal.juniper.net/s/article/2024-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Confidential-information-in-logs-can-be-accessed-by-another-user-CVE-2024-39532
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9af9ae9");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA82992");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:N/VI:N/VA:N/SC:H/SI:L/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39532");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  # All versions before 21.2R3-S9;
  {'min_ver':'0.0','fixed_ver':'21.2R3-S9'}, 

  # 21.4 versions before 21.4R3-S9;
  {'min_ver':'21.4','fixed_ver':'21.4R3-S9'}, 

  # 22.2 versions before 22.2R2-S1, 22.2R3;
  {'min_ver':'22.2','fixed_ver':'22.2R2-S1','fixed_display':'22.2R2-S1, 22.2R3'}, 

  # 22.3 versions before 22.3R1-S1, 22.3R2;
  {'min_ver':'22.3','fixed_ver':'22.3R1-S1','fixed_display':'22.3R1-S1, 22.3R2'},

  # 22.4 versions before 22.4R1;
  {'min_ver':'22.4','fixed_ver':'22.4R1'},

  # 22.1-EVO versions before 22.1R3-EVO;
  {'min_ver':'22.1-EVO','fixed_ver':'22.1R3-EVO'}, 

  # 22.2-EVO versions before 22.2R2-S1-EVO, 22.2R3-EVO;
  {'min_ver':'22.2-EVO','fixed_ver':'22.2R2-S1-EVO','fixed_display':'22.2R2-S1-EVO, 22.2R3-EVO'}, 

  # 22.3-EVO versions before 22.3R1-S1-EVO, 22.3R2-EVO;
  {'min_ver':'22.3-EVO','fixed_ver':'22.3R1-S1-EVO','fixed_display':'22.3R1-S1-EVO, 22.3R2-EVO'},

  # 22.4-EVO versions before 22.4R1-EVO;
  {'min_ver':'22.4-EVO','fixed_ver':'22.4R1-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
