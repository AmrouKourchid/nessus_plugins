#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212709);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2024-47504");
  script_xref(name:"JSA", value:"JSA88134");
  script_xref(name:"IAVA", value:"2024-A-0650");

  script_name(english:"Juniper Junos OS Vulnerability (JSA88134)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA88134
advisory.

  - An Improper Validation of Specified Type of Input vulnerability in the packet forwarding engine (pfe)
    Juniper Networks Junos OS on SRX5000 Series allows an unauthenticated, network based attacker to cause a
    Denial of Service (Dos). (CVE-2024-47504)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA88134");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88134");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}


include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^SRX5[0-9]{3}")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'22.1R1 ', 'model':'^SRX5[0-9]{3}', 'fixed_ver':'22.2R3-S5'},
  {'min_ver':'22.3', 'model':'^SRX5[0-9]{3}', 'fixed_ver':'22.3R3-S4'},
  {'min_ver':'22.4', 'model':'^SRX5[0-9]{3}', 'fixed_ver':'22.4R3-S4'},
  {'min_ver':'23.2', 'model':'^SRX5[0-9]{3}', 'fixed_ver':'23.2R2-S2'},
  {'min_ver':'23.4', 'model':'^SRX5[0-9]{3}', 'fixed_ver':'23.4R2-S1'},
  {'min_ver':'24.2', 'model':'^SRX5[0-9]{3}', 'fixed_ver':'24.2R1-S1', 'fixed_display':'24.2R1-S1 / 24.2R2'},
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:"show chassis cluster status");

if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"Chassis cluster is not enabled", multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because the chassis cluster is enabled");
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
