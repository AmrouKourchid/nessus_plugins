#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151638);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2021-0288");
  script_xref(name:"JSA", value:"JSA11190");
  script_xref(name:"IAVA", value:"2021-A-0324-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11190)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11190
advisory.

  - A vulnerability in the processing of specific MPLS packets in Juniper Networks Junos OS on MX Series,
    EX9200 Series with Trio-based MPC (Modular Port Concentrator) may cause FPC to crash and lead to a Denial
    of Service (DoS) condition. Continued receipt of this packet will sustain the Denial of Service (DoS)
    condition. (CVE-2021-0288)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2021-07-Security-Bulletin-Junos-OS-MX-Series-EX9200-Series-FPC-may-crash-upon-receipt-of-specific-MPLS-packet-affecting-Trio-based-MPCs-CVE-2021-0288
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2b9d7fc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11190");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0288");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (model !~ "^(EX92|MX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S12', 'model':'^(EX92|MX)'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13', 'model':'^(EX92|MX)'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S5', 'model':'^(EX92|MX)'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13', 'model':'^(EX92|MX)'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S8', 'model':'^(EX92|MX)'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5', 'model':'^(EX92|MX)'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S8', 'model':'^(EX92|MX)'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S8', 'model':'^(EX92|MX)'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5', 'model':'^(EX92|MX)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2', 'model':'^(EX92|MX)'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6', 'model':'^(EX92|MX)'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S3', 'model':'^(EX92|MX)'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4', 'model':'^(EX92|MX)', 'fixed_display':'19.4R1-S4, 19.4R2-S4'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R3-S2', 'model':'^(EX92|MX)'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3', 'model':'^(EX92|MX)'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S2', 'model':'^(EX92|MX)', 'fixed_display':'20.2R2-S2, 20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2', 'model':'^(EX92|MX)'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2', 'model':'^(EX92|MX)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
