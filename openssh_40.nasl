#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44075);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2005-2666", "CVE-2007-4654", "CVE-2004-2760");

  script_name(english:"OpenSSH < 4.0 known_hosts Plaintext Host Information Disclosure");
  script_summary(english:"Checks for remote SSH version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by an information disclosure
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSH prior to 4.0.  Versions of OpenSSH earlier than 4.0 are
affected by an information disclosure vulnerability because the
application stores hostnames, IP addresses, and keys in plaintext in
the 'known_hosts' file.  A local attacker, exploiting this flaw, could
gain access to sensitive information that could be used in subsequent
attacks.");

  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-4.0");
  script_set_attribute(attribute:"see_also", value:"http://nms.csail.mit.edu/projects/ssh/");
  script_set_attribute(attribute:"see_also", value:"http://www.eweek.com/c/a/Security/Researchers-Reveal-Holes-in-Grid/");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_cwe_id(16, 255, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable, Inc.");
  script_family(english:"Misc.");

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
  {'fixed_version': '4.0'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
