#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202114);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/19");

  script_cve_id(
    "CVE-2024-39520",
    "CVE-2024-39521",
    "CVE-2024-39522",
    "CVE-2024-39523",
    "CVE-2024-39524"
  );
  script_xref(name:"JSA", value:"JSA82975");
  script_xref(name:"IAVA", value:"2024-A-0385");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA82975)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA82975 advisory.

  - An Improper Neutralization of Special Elements vulnerability in Juniper Networks Junos OS Evolved commands
    allows a local, authenticated attacker with low privileges to escalate their privileges to 'root' leading
    to a full compromise of the system. (CVE-2024-39520, CVE-2024-39521, CVE-2024-39522, CVE-2024-39523,
    CVE-2024-39524)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-07-Security-Bulletin-Junos-OS-Evolved-Multiple-CLI-parameter-processing-issues-allowing-privilege-escalation-resolved
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e28ba556");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA82975");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39524");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

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
if (model !~ "^(ACX|PTX|QFX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R3-S8-EVO', 'model':'^(ACX|PTX|QFX)'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S7-EVO', 'model':'^(ACX|PTX|QFX)'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-EVO', 'model':'^(ACX|PTX|QFX)'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R2-EVO', 'model':'^(ACX|PTX|QFX)'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R2-EVO', 'model':'^(ACX|PTX|QFX)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
