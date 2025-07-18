#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130514);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id(
    "CVE-2015-6564",
    "CVE-2015-8325",
    "CVE-2016-6210",
    "CVE-2016-6515",
    "CVE-2016-10009",
    "CVE-2016-10010",
    "CVE-2016-10011",
    "CVE-2016-10012"
  );
  script_bugtraq_id(
    76317,
    86187,
    91812,
    92212,
    94968,
    94972,
    94975
  );
  script_xref(name:"JSA", value:"JSA10940");

  script_name(english:"Juniper JSA10940");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 12.3X48-D55, 12.3R12-S13, 15.1X49-D100, 15.1F6-S12,
16.1R3-S4, 16.2R1-S4, 17.1R1-S2, or 17.2R1. It is, therefore, affected by a vulnerability as referenced in the JSA10940
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://supportportal.juniper.net/s/article/2019-07-Security-Bulletin-Junos-OS-Multiple-Vulnerabilities-in-OpenSSH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6abd1bf");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10940");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10009");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-10012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S13'},
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D55'},
  {'min_ver':'15.1', 'fixed_ver':'15.1F6-S12', 'fixed_display':'15.1F6-S12, 15.1R7'},
  {'min_ver':'15.1R6', 'fixed_ver':'15.1R5-S4', 'fixed_display':'15.1R5-S4, 15.1R6-S1'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D100'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R3-S4', 'fixed_display':'16.1R3-S4, 16.1R5'},
  {'min_ver':'16.1R4', 'fixed_ver':'16.1R4-S3'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R1-S4', 'fixed_display':'16.2R1-S4, 16.2R2'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R1-S2', 'fixed_display':'17.1R1-S2, 17.1R2'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R1'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
