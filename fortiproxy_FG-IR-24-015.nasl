#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191084);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/22");

  script_cve_id("CVE-2024-21762");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/16");
  script_xref(name:"IAVA", value:"2024-A-0079-S");

  script_name(english:"Fortinet FortiProxy Out-of-bound Write in sslvpnd (FG-IR-24-015)");

  script_set_attribute(attribute:"synopsis", value:
"The version of FortiProxy installed on the remote host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiProxy installed on the remote host affected by an out-of-bounds write vulnerability in sslvpnd
that can allow an attacker to execute unauthorized code or commands via specifically crafted requests.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-24-015");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiProxy version 2.0.14, 7.0.15, 7.2.9, 7.4.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21762");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiproxy");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/FortiProxy/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiProxy';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/FortiProxy/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '1.0', 'fixed_version' : '2.0.14' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.15' },
  { 'min_version' : '7.2', 'fixed_version' : '7.2.9' },
  { 'min_version' : '7.4', 'fixed_version' : '7.4.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
