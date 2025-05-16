#%NASL_MIN_LEVEL 80900
##
# (c) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208751);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/05");

  script_cve_id("CVE-2024-37404");
  script_xref(name:"IAVA", value:"2024-A-0639-S");

  script_name(english:"Ivanti Policy Secure 22.x < 22.7R1.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A NAC solution installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Ivanti Policy Secure installed on the remote host is prior to 22.7R1.1. It is, therefore, 
affected by a remote code execution vulnerability due to improper input validation in the admin portal. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-and-Policy-Secure-CVE-2024-37404
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7269e19a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ivanti Pulse Policy Secure 22.7R1.1 (Build 1321) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37404");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ivanti Connect Secure Authenticated Remote Code Execution via OpenSSL CRLF Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:policy_secure");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulse_secure:pulse_policy_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_policy_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Policy Secure");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Pulse Policy Secure', port:port);

var constraints = [
  {'fixed_version':'22.7.1.1321', 'fixed_display': '22.7R1.1 (Build 1321)'} 
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

