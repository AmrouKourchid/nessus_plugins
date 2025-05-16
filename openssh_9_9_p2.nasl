#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216476);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2025-26465");
  script_xref(name:"IAVA", value:"2025-A-0126-S");

  script_name(english:"OpenSSH < 9.9p2 MitM");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a man in the middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSH installed on the remote host is prior to 9.9p2. It is, therefore, affected by a man in the
middle (MITM) vulnerability. ssh(1) in OpenSSH versions 6.8p1 to 9.9p1 (inclusive) contained a logic error that allowed
an on-path attacker (a.k.a MITM) to impersonate any server when the VerifyHostKeyDNS option is enabled. This option is
off by default.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-9.9p2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 9.9p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26465");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssh_detect.nbin");
  script_require_keys("installed_sw/OpenSSH");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

# Not testing for non-default VerifyHostKeyDNS option
if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, 'OpenSSH');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'min_version': '6.8p1', 'fixed_version': '9.9p2', 'fixed_display': '9.9p2'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

