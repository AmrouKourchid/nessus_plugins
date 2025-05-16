#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73079);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2014-1692", "CVE-2014-2532");
  script_bugtraq_id(65230, 66355);

  script_name(english:"OpenSSH < 6.6 Multiple Vulnerabilities");
  script_summary(english:"Checks OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 6.6. It is, therefore, affected by the following
vulnerabilities :

  - A flaw exists due to a failure to initialize certain
    data structures when makefile.inc is modified to enable
    the J-PAKE protocol. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in a
    denial of service condition and potentially the
    execution of arbitrary code. (CVE-2014-1692)

  - An error exists related to the 'AcceptEnv' configuration
    setting in sshd_config due to improper processing of
    wildcard characters. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    bypass intended environment restrictions.
    (CVE-2014-2532)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-6.6");
  script_set_attribute(attribute:"see_also", value:"https://lists.gt.net/openssh/dev/57663#57663");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH version 6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable, Inc.");

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

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'fixed_version': '6.6'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
