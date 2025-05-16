#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189373);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-0204");
  script_xref(name:"CEA-ID", value:"CEA-2024-0002");

  script_name(english:"Fortra GoAnywhere Managed File Transfer (MFT) < 7.4.1 Authentication Bypass (CVE-2024-0204)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Fortra GoAnywhere Managed File Transfer (MFT) running on the
remote web server is < 7.4.1. It is, therefore, affected by an authentication bypass vulnerability. This can allow an
unauthenticated attacker to create an admin user via the administration portal.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortra.com/security/advisory/fi-2024-001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortra GoAnywhere Managed File Transfer (MFT) 7.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0204");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Fortra GoAnywhere MFT Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:helpsystems:goanywhere_managed_file_transfer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortra_goanywhere_mft_web_detect.nbin");
  script_require_keys("installed_sw/Fortra GoAnywhere MFT", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8000);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:8000);

var app_info = vcf::get_app_info(app:'Fortra GoAnywhere MFT', port:port, webapp:TRUE);

var constraints = [
  { 'min_version': '6.0.1', 'fixed_version':'7.4.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
