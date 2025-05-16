#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209801);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2021-42753");

  script_name(english:"Fortinet FortiWeb Arbitrary file/directory deletion (FG-IR-21-158)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiWeb installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-21-158 advisory.

  - An improper limitation of a pathname to a restricted directory ('Path Traversal') vulnerability [CWE-22]
    in FortiWeb management interface 6.4.1 and below, 6.3.15 and below, 6.2.x, 6.1.x, 6.0.x, 5.9.x and 5.8.x
    may allow an authenticated attacker to perform an arbitrary file and directory deletion in the device
    filesystem. (CVE-2021-42753)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-158");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiWeb version 6.3.16/6.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42753");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiweb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'FortiWeb';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '5.8.0', 'max_version' : '5.8.0', 'fixed_version' : '6.3.16' },
  { 'min_version' : '5.9.0', 'max_version' : '5.9.0', 'fixed_version' : '6.3.16' },
  { 'min_version' : '6.0.0', 'max_version' : '6.0.0', 'fixed_version' : '6.3.16' },
  { 'min_version' : '6.1.0', 'max_version' : '6.1.0', 'fixed_version' : '6.3.16' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.0', 'fixed_version' : '6.3.16' },
  { 'min_version' : '6.3.0', 'max_version' : '6.3.15', 'fixed_version' : '6.3.16' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.1', 'fixed_version' : '6.4.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
