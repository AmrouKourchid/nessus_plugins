#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178675);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2020-1629");
  script_xref(name:"JSA", value:"JSA11009");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11009
advisory.

  - A race condition vulnerability on Juniper Network Junos OS devices may cause the routing protocol daemon
    (RPD) process to crash and restart while processing a BGP NOTIFICATION message. This issue affects Juniper
    Networks Junos OS: 16.1 versions prior to 16.1R7-S6; 16.2 versions prior to 16.2R2-S11; 17.1 versions
    prior to 17.1R2-S11, 17.1R3-S1; 17.2 versions prior to 17.2R1-S9, 17.2R3-S3; 17.2 version 17.2R2 and later
    versions; 17.2X75 versions prior to 17.2X75-D105, 17.2X75-D110; 17.3 versions prior to 17.3R2-S5,
    17.3R3-S6; 17.4 versions prior to 17.4R2-S7, 17.4R3; 18.1 versions prior to 18.1R3-S8; 18.2 versions prior
    to 18.2R3-S3; 18.2X75 versions prior to 18.2X75-D410, 18.2X75-D420, 18.2X75-D50, 18.2X75-D60; 18.3
    versions prior to 18.3R1-S5, 18.3R2-S2, 18.3R3; 18.4 versions prior to 18.4R2-S2, 18.4R3; 19.1 versions
    prior to 19.1R1-S2, 19.1R2; 19.2 versions prior to 19.2R1-S4, 19.2R2. This issue does not affect Juniper
    Networks Junos OS prior to version 16.1R1. (CVE-2020-1629)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2020-04-Security-Bulletin-Junos-OS-A-race-condition-vulnerability-may-cause-RPD-daemon-to-crash-when-processing-a-BGP-NOTIFICATION-message-CVE-2020-1629
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e2988a8");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11009");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1629");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  {'min_ver':'16.1', 'fixed_ver':'16.1R7-S6'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R2-S11'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S11'},
  {'min_ver':'17.1R3', 'fixed_ver':'17.1R3-S1'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R1-S9', 'fixed_display':'17.2R1-S9, 17.2R2'},
  {'min_ver':'17.2R2', 'fixed_ver':'17.2R3-S3'},
  {'min_ver':'17.2X75', 'fixed_ver':'17.2X75-D105', 'fixed_display':'17.2X75-D105, 17.2X75-D110'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R2-S5'},
  {'min_ver':'17.3R3', 'fixed_ver':'17.3R3-S6'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S7', 'fixed_display':'17.4R2-S7, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S8'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S3'},
  {'min_ver':'18.2X75', 'fixed_ver':'18.2X75-D410', 'fixed_display':'18.2X75-D410, 18.2X75-D420, 18.2X75-D50, 18.2X75-D60'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R1-S5', 'fixed_display':'18.3R1-S5, 18.3R2-S2, 18.3R3'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S2', 'fixed_display':'18.4R2-S2, 18.4R3'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S2', 'fixed_display':'19.1R1-S2, 19.1R2'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S4', 'fixed_display':'19.2R1-S4, 19.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
