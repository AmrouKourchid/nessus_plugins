#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234007);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id("CVE-2024-46671");

  script_name(english:"Fortinet FortiWeb Incorrect user management in widgets dashboard (FG-IR-24-184)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiWeb installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-24-184 advisory.

  - An Incorrect User Management vulnerability [CWE-286] in FortiWeb version 7.6.2 and below, version 7.4.6
    and below, version 7.2.10 and below, version 7.0.11 and below widgets dashboard may allow an authenticated
    attacker with at least read-only admin permission to perform operations on the dashboard of other
    administrators via crafted requests. (CVE-2024-46671)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-24-184");
  script_set_attribute(attribute:"solution", value:
"For 7.0.x, see vendor advisory. For 7.2.x, upgrade to FortiWeb version 7.2.11 or later. For 7.4.x, upgrade to FortiWeb
version 7.4.7 or later. For 7.6.x, upgrade to FortiWeb version 7.6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:M/C:P/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiweb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'FortiWeb';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.0.999999', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.10', 'fixed_version' : '7.2.11' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.6', 'fixed_version' : '7.4.7' },
  { 'min_version' : '7.6.0', 'max_version' : '7.6.2', 'fixed_version' : '7.6.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
