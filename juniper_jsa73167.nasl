#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182925);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2023-44201");
  script_xref(name:"JSA", value:"JSA73167");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Vulnerability (JSA73167)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73167
advisory.

  - An Incorrect Permission Assignment for Critical Resource vulnerability in a specific file of Juniper
    Networks Junos OS and Junos OS Evolved allows a local authenticated attacker to read configuration changes
    without having the permissions. (CVE-2023-44201)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA73167");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-A-local-attacker-can-retrieve-sensitive-information-and-elevate-privileges-on-the-devices-to-an-authorized-user-CVE-2023-44201
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c899804e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73167");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S4'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S4-EVO'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S4'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R3-S2-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S2'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R3-S2-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2-S2'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-S1-EVO'},
  {'min_ver':'21.3R3', 'fixed_ver':'21.3R3-S1'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2-S1', 'fixed_display':'21.4R2-S1, 21.4R3'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R2-S2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
