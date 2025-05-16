##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148680);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2021-0275");
  script_xref(name:"JSA", value:"JSA11166");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11166)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability (XSS in J-Web) as referenced in the JSA11166
advisory. 

Note: Nessus found J-Web enabled [set system services web-management http(s)] on this device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11166");
  script_set_attribute(attribute:"solution", value:
"- Disable J-Web.
- User firewall filters to restrict / limit access to J-Web; only allow access to trusted networks, hosts and users.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0275");

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

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX|SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'16.1', 'fixed_ver':'16.1R7-S7'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R2-S11'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S11'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R3-S3'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R2-S5'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S9'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S9'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S7'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R1-S7'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S6'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2-S1'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2'}
];
if (model =~ '^EX')
{
  append_element(var:vuln_ranges, value:{'min_ver':'12.3', 'fixed_ver':'12.3R12-S15'});
  append_element(var:vuln_ranges, value:{'min_ver':'15.1', 'fixed_ver':'15.1R7-S6'});
}
if (model =~ '^SRX')
{
  append_element(var:vuln_ranges, value:{'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D95'});
  append_element(var:vuln_ranges, value:{'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D200'});
}

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  var pattern = "^set system services web-management http(s)?";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as J-Web is not enabled');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
