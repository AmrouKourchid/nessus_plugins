#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201921);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2023-49583");

  script_name(english:"Node.js Module @sap/xssec < 3.6.0 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A module in the Node.js JavaScript run-time environment is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The nodejs module @sap/xssec detected on the host is prior to version 3.6.0. It is, therefore, affected by a privilege
escalation vulnerability. An unauthenticated, remote attacker can exploit this to gain arbitrary permissions within the
applicaiton.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3411067");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3412456");
  script_set_attribute(attribute:"solution", value:
"Upgrade to @sap/xssec version 3.6.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49583");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:%40sap%2fxssec");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_modules_win_installed.nbin", "nodejs_modules_linux_installed.nbin", "nodejs_modules_mac_installed.nbin");
  script_require_keys("installed_sw/Node.js", "Host/nodejs/modules/enumerated");

  exit(0);
}

include('vcf_extras_nodejs.inc');

var app_info = vcf_extras::nodejs_modules::get_app_info(app:'@sap/xssec');

var constraints = [
  { 'fixed_version' : '3.6.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
