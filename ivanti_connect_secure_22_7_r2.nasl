#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208752);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/05");

  script_cve_id("CVE-2024-37404");
  script_xref(name:"IAVA", value:"2024-A-0639-S");

  script_name(english:"Ivanti Connect Secure 9.1Rx < 9.1R18.9 / 22.x < 22.7R2.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A VPN solution installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Ivanti Connect Secure installed on the remote host is 9.1Rx prior to 9.1R18.9, 22.x prior to 22.7R2.1. 
It is, therefore, affected by a remote code execution vulnerability due to improper input validation
in the admin portal. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-and-Policy-Secure-CVE-2024-37404
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7269e19a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ivanti Connect Secure 9.1R18.9, 22.7R2.1, 22.7R2.2 or later.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:connect_secure");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulse_secure:connect_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('vcf_extras.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

# 9.1.18R9 to be released on Oct 15th, guestimating the build will be over 25999
var constraints = [
  {'max_version':'9.1.18.25609', 'fixed_version':'9.1.18.25999',  'fixed_display':'9.1R18.9'}, 
  {'min_version':'22.0', 'fixed_version':'22.7.2.3191',   'fixed_display':'22.7R2.1 (Build 3191)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
