#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202123);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/19");

  script_cve_id("CVE-2024-39533");
  script_xref(name:"JSA", value:"JSA82993");
  script_xref(name:"IAVA", value:"2024-A-0385");

  script_name(english:"Juniper Junos OS Vulnerability (JSA82993)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA82993
advisory.

  - An Unimplemented or Unsupported Feature in the UI vulnerability in Juniper Networks Junos OS on QFX5000
    Series and EX4600 Series allows an unauthenticated, network-based attacker to cause a minor integrity
    impact to downstream networks. (CVE-2024-39533)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-07-Security-Bulletin-Junos-OS-QFX5000-Series-and-EX4600-Series-Output-firewall-filter-is-not-applied-if-certain-match-criteria-are-used-CVE-2024-39533
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59f02f1d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA82993");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39533");

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
if (model !~ "^(EX46|QFX5)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S6', 'model':'^(EX46|QFX5)'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S5', 'model':'^(EX46|QFX5)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S3', 'model':'^(EX46|QFX5)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S2', 'model':'^(EX46|QFX5)'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3', 'model':'^(EX46|QFX5)'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2', 'model':'^(EX46|QFX5)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
