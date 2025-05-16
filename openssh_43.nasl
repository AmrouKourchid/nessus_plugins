#
# (C) Tenable, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44076);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2006-0225");
  script_bugtraq_id(16369);

  script_name(english:"OpenSSH  < 4.3 scp Command Line Filename Processing Command Injection");
  script_summary(english:"Checks SSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of SSH running on the remote host has a command injection
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host is potentially affected by an arbitrary command execution
vulnerability.  The scp utility does not properly sanitize
user-supplied input prior to using a system() function call.  A local
attacker could exploit this by creating filenames with shell
metacharacters, which could cause arbitrary code to be executed if
copied by a user running scp."
  );
  script_set_attribute(attribute:"see_also",value:"https://bugzilla.mindrot.org/show_bug.cgi?id=1094");
  script_set_attribute(attribute:"see_also",value:"http://www.openssh.com/txt/release-4.3");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 4.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable, Inc.");

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
  {'fixed_version': '4.3'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
