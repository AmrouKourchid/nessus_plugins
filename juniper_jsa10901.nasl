#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121389);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0002");
  script_xref(name:"JSA", value:"JSA10901");

  script_name(english:"Junos OS: EX2300 and EX3400 series: Certain stateless firewall filter rules might not take effect (JSA10901)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability in which stateless 
firewall filter configuration that uses the action 'policer' in 
combination with other actions might not take effect.");
  # https://supportportal.juniper.net/s/article/2019-01-Security-Bulletin-Junos-OS-EX2300-and-EX3400-series-Certain-stateless-firewall-filter-rules-might-not-take-effect-CVE-2019-0002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?161988b1");
  # https://www.juniper.net/documentation/en_US/junos/topics/reference/command-summary/show-pfe-filter.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad0738dc");
  # https://supportportal.juniper.net/s/article/2019-01-Security-Bulletin-Junos-OS-EX2300-and-EX3400-series-Certain-stateless-firewall-filter-rules-might-not-take-effect-CVE-2019-0002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?161988b1");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10901");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0002");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX2300|EX34)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D590', 'model':'^(EX2300|EX34)'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3', 'model':'^(EX2300|EX34)'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2', 'model':'^(EX2300|EX34)'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
