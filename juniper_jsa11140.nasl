##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148648);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2021-0247");
  script_xref(name:"JSA", value:"JSA11140");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11140
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://supportportal.juniper.net/s/article/2021-04-Security-Bulletin-Junos-OS-PTX-Series-QFX-Series-Due-to-a-race-condition-input-loopback-firewall-filters-applied-to-interfaces-may-not-operate-even-when-listed-in-the-running-configuration-CVE-2021-0247
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc5ae075");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11140");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(PTX|QFX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'14.1', 'fixed_ver':'14.1R1', 'model':'^(PTX|QFX)'},
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D53', 'model':'^QFX'},
  {'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D593', 'model':'^QFX'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R7-S7', 'model':'^(PTX|QFX)'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R2-S11', 'model':'^(PTX|QFX)', 'fixed_display':'16.2R2-S11, 16.2R3'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S11', 'model':'^(PTX|QFX)'},
  {'min_ver':'17.1R3', 'fixed_ver':'17.1R3-S2', 'model':'^(PTX|QFX)'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R1-S9', 'model':'^(PTX|QFX)'},
  {'min_ver':'17.2R2', 'fixed_ver':'17.2R3-S3', 'model':'^(PTX|QFX)'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R2-S5', 'model':'^(PTX|QFX)'},
  {'min_ver':'17.3R3', 'fixed_ver':'17.3R3-S7', 'model':'^(PTX|QFX)'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S9', 'model':'^(PTX|QFX)', 'fixed_display':'17.4R2-S9, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S9', 'model':'^(PTX|QFX)'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S6', 'model':'^(PTX|QFX)'},
  {'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S3', 'model':'^(PTX|QFX)'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R1-S7', 'model':'^(PTX|QFX)', 'fixed_display':'18.3R1-S7, 18.3R2-S3'},
  {'min_ver':'18.3R2', 'fixed_ver':'18.3R3-S1', 'model':'^(PTX|QFX)'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S5', 'model':'^(PTX|QFX)', 'fixed_display':'18.4R1-S5, 18.4R2-S3, 18.4R3'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S4', 'model':'^(PTX|QFX)', 'fixed_display':'19.1R1-S4, 19.1R2-S1, 19.1R3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S3', 'model':'^(PTX|QFX)', 'fixed_display':'19.2R1-S3, 19.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
