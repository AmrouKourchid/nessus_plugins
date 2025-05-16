#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
##

include('compat.inc');

if (description)
{
  script_id(171133);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2023-25136");
  script_xref(name:"IAVA", value:"2023-A-0073-S");

  script_name(english:"OpenSSH 9.1 Double Free");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a double free vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSH installed on the remote host is 9.1. It is, therefore, affected by a double-free vulnerability
during options.kex_algorithms handling. The double free can be triggered by an unauthenticated attacker in the default
configuration; however, the vulnerability discoverer reports that 'exploiting this vulnerability will not be easy.'

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-9.2");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2023/02/02/2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25136");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssh_detect.nbin");
  script_require_keys("installed_sw/OpenSSH", "Settings/ParanoidReport");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

# only default configurations are vuln
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'min_version': '9.1', 'fixed_version': '9.2'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
