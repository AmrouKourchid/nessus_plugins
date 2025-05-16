#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235087);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/03");

  script_cve_id("CVE-2023-44221", "CVE-2023-5970");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/05/22");

  script_name(english:"SonicWall Secure Mobile Access < 10.2.1.10-62sv (SNWLID-2023-0018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of SonicWall Secure Mobile Access installed on the remote host is prior to 10.2.1.10-62sv. It is, therefore,
affected by multiple vulnerabilities as referenced in the SNWLID-2023-0018 advisory:

  - Improper neutralization of special elements in the SMA100 SSL-VPN management interface allows a remote
    authenticated attacker with administrative privilege to inject arbitrary commands as a 'nobody' user, potentially
    leading to OS Command Injection Vulnerability. (CVE-2023-44221)

  - Improper authentication in the SMA100 SSL-VPN virtual office portal allows a remote authenticated attacker to
    create an identical external domain user using accent characters, resulting in an MFA bypass. (CVE-2023-5970)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2023-0018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fba2b7c0");
  script_set_attribute(attribute:"solution", value:
"Upgrade SonicWall Secure Mobile Access version 10.2.1.10-62sv or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5970");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:sonicwall:firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sma_web_detect.nbin");
  script_require_keys("installed_sw/SonicWall Secure Mobile Access", "Settings/ParanoidReport");

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app_name = 'SonicWall Secure Mobile Access';

get_install_count(app_name:app_name, exit_if_zero:TRUE);

# We cannot test for vulnerable models
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var port = get_http_port(default:443, embedded:TRUE);

var app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

var constraints = [
  { 'max_version' : '10.2.1.9.57', 'fixed_version' : '10.2.1.10.62', 'fixed_display' : '10.2.1.10-62sv' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
