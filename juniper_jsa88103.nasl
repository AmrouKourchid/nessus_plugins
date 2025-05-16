#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208450);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2024-39526");
  script_xref(name:"JSA", value:"JSA88103");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS Vulnerability (JSA88103)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88103
advisory.

  - An Improper Handling of Exceptional Conditions vulnerability in packet processing of Juniper Networks
    Junos OS on MX Series with MPC10/MPC11/LC9600 line cards, EX9200 with EX9200-15C lines cards, MX304
    devices, and Juniper Networks Junos OS Evolved on PTX Series, allows an attacker sending malformed DHCP
    packets to cause ingress packet processing to stop, leading to a Denial of Service (DoS). Continued
    receipt and processing of these packets will create a sustained Denial of Service (DoS) condition.
    (CVE-2024-39526)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-MX-Series-with-MPC10-MPC11-LC9600-MX304-EX9200-PTX-Series-Receipt-of-malformed-DHCP-packets-causes-interfaces-to-stop-processing-packets-CVE-2024-39526
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?606f0b83");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88103");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

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
if (model !~ "^(EX9200|MX|MX304|PTX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.2R3-S7', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'19.3R1-EVO', 'fixed_ver':'21.2R3-S8-EVO', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S6', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S7-EVO', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S6-EVO', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S3', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S5-EVO', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-S3-EVO', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R3-S1-EVO', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'23.2-EVO', 'fixed_ver':'23.2R2-S2-EVO', 'model':'^(EX9200|MX|MX304|PTX)'},
  {'min_ver':'23.4-EVO', 'fixed_ver':'23.4R2-EVO', 'model':'^(EX9200|MX|MX304|PTX)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
