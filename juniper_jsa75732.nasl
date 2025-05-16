#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201920);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/05");

  script_cve_id("CVE-2024-21593");
  script_xref(name:"JSA", value:"JSA75732");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Vulnerability (JSA75732)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA75732
advisory.

  - An Improper Check or Handling of Exceptional Conditions vulnerability in the Packet Forwarding Engine
    (PFE) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated, adjacent attacker to
    cause a Denial of Service (DoS). If an attacker sends a specific MPLS packet, which upon processing,
    causes an internal loop, that leads to a PFE crash and restart. Continued receipt of these packets leads
    to a sustained Denial of Service (DoS) condition. Circuit cross-connect (CCC) needs to be configured on
    the device for it to be affected by this issue. This issue only affects MX Series with MPC10, MPC11,
    LC9600, and MX304. This issue affects: Juniper Networks Junos OS 21.4 versions from 21.4R3 earlier than
    21.4R3-S5; 22.2 versions from 22.2R2 earlier than 22.2R3-S2; 22.3 versions from 22.3R1 earlier than
    22.3R2-S2; 22.3 versions from 22.3R3 earlier than 22.3R3-S1 22.4 versions from 22.4R1 earlier than
    22.4R2-S2, 22.4R3; 23.2 versions earlier than 23.2R1-S1, 23.2R2. (CVE-2024-21593)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA75732");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA75732");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21593");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
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
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(MPC1[01]|LC9600|MX304)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5', 'model':'^(MPC1[01]|LC9600|MX304)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2', 'model':'^(MPC1[01]|LC9600|MX304)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'model':'^(MPC1[01]|LC9600|MX304)'},
  {'min_ver':'22.3R3', 'fixed_ver':'22.3R3-S1', 'model':'^(MPC1[01]|LC9600|MX304)'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S2', 'model':'^(MPC1[01]|LC9600|MX304)', 'fixed_display':'22.4R2-S2, 22.4R3'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R1-S1', 'model':'^(MPC1[01]|LC9600|MX304)', 'fixed_display':'23.2R1-S1, 23.2R2'}

];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set interface encapsulation ethernet-ccc"))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
