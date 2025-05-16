#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202121);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2024-39565");
  script_xref(name:"JSA", value:"JSA83023");

  script_name(english:"Juniper Junos OS Vulnerability (JSA83023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA83023
advisory.

  - An Improper Neutralization of Data within XPath Expressions ('XPath Injection') vulnerability in J-Web
    shipped with Juniper Networks Junos OS allows an unauthenticated, network-based attacker to execute remote
    commands on the target device. (CVE-2024-39565)

Note: Nessus found J-Web enabled [set system services web-management http(s)] on this device.");
  script_set_attribute(attribute:"see_also", value:"https://support.juniper.net/support/downloads/?p=283");
  # https://www.first.org/cvss/calculator/v4-0#CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/AU:Y/R:I/V:C/RE:L/U:Amber
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e33ab8cf");
  # https://supportportal.juniper.net/s/article/2024-07-Security-Bulletin-Junos-OS-SRX-Series-EX-Series-J-Web-An-unauthenticated-network-based-attacker-can-perform-XPATH-injection-attack-against-a-device-CVE-2024-39565
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f120ed69");
  script_set_attribute(attribute:"solution", value:
"- Disable J-Web and using only alternate options such as Netconf over SSH for device management.
- Restricting the use of J-Web to low-privileged accounts only.
- Deploying the appropriate IDP Signature on devices which do not have J-Web enabled which protect the device downstream which requires J-Web to be enabled.

When remediating, please also refer to Juniper advisory JSA83023.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX|J|S|SRX|with)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.2R3-S8', 'model':'^(EX|J|S|SRX|with)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S7', 'model':'^(EX|J|S|SRX|with)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S4', 'model':'^(EX|J|S|SRX|with)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S3', 'model':'^(EX|J|S|SRX|with)'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3-S2', 'model':'^(EX|J|S|SRX|with)'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2', 'model':'^(EX|J|S|SRX|with)'},
  {'min_ver':'23.4', 'fixed_ver':'23.4R1-S1', 'model':'^(EX|J|S|SRX|with)', 'fixed_display':'23.4R1-S1, 23.4R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:"show configuration | display set");
if (!empty_or_null(buf))
{
  override = FALSE;
  if(!junos_check_config(buf:buf, pattern:"^set system services web-management http(s)?")) 
  {
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  }
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

