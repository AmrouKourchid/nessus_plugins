#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130455);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/16");

  script_cve_id("CVE-2019-16905");
  script_xref(name:"IAVA", value:"2019-A-0400-S");

  script_name(english:"OpenSSH 7.7 < 8.1");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"OpenSSH 7.7 through 7.9 and 8.x before 8.1, when compiled with an experimental key type, has a pre-authentication
integer overflow if a client or server is configured to use a crafted XMSS key. This leads to memory corruption and
local code execution because of an error in the XMSS key parsing algorithm. NOTE: the XMSS implementation is
considered experimental in all released OpenSSH versions, and there is no supported way to enable it when building
portable OpenSSH.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2019/10/09/1");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-8.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16905");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

# only vuln when compiled with an experimental key type
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'min_version': '7.7', 'fixed_version': '8.1'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
