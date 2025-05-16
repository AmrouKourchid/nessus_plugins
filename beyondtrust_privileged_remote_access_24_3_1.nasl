#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213465);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2024-12356", "CVE-2024-12686");
  script_xref(name:"IAVA", value:"2025-A-0004");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/12/27");

  script_name(english:"BeyondTrust Privileged Remote Access (PRA) <= 24.3.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of BeyondTrust Privileged Remote Access (PRA) running on the remote host is prior or equal to 24.3.1. It
is, therefore, potentially affected by multiple vulnerabilities.

  - All BeyondTrust Privileged Remote Access (PRA) versions contain a command injection vulnerability which can be
  exploited through a malicious client request. Successful exploitation of this vulnerability can allow an
  unauthenticated remote attacker to execute underlying operating system commands within the context of the
  site user. This issue is fixed through a patch available for all supported releases of RS & PRA 22.1.x and
  higher. (CVE-2024-12356)

  - All BeyondTrust Privileged Remote Access (PRA) versions contain a command injection vulnerability that can be 
  exploited by a user with existing administrative privileges to upload a malicious file. Successful 
  exploitation of this vulnerability can allow a remote attacker to execute underlying operating system
  commands within the context of the site user. This issue is fixed through a patch available for all
  supported releases of RS & PRA 22.1.x and higher. (CVE-2024-12686)

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  # https://www.beyondtrust.com/remote-support-saas-service-security-investigation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2193043d");
  script_set_attribute(attribute:"see_also", value:"https://www.beyondtrust.com/trust-center/security-advisories/bt24-10");
  script_set_attribute(attribute:"see_also", value:"https://www.beyondtrust.com/trust-center/security-advisories/bt24-11");
  script_set_attribute(attribute:"solution", value:
"Upgrade BeyondTrust Privileged Remote Access (PRA) according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-12356");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'BeyondTrust Privileged Remote Access (PRA) and Remote Support (RS) unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:beyondtrust:privileged_remote_access");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("beyondtrust_privileged_remote_access_detect.nbin");
  script_require_keys("installed_sw/BeyondTrust Privileged Remote Access", "Settings/ParanoidReport");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = 'BeyondTrust Privileged Remote Access';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  { 'max_version' : '24.3.1', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);