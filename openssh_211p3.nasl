#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17839);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2000-0999");

  script_name(english:"OpenSSH < 2.1.1p3 Format String Privilege Escalation");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OpenSSH server has a format string vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the banner, a version of OpenSSH earlier than 2.1.1p3 is 
running on the remote host.  As such, it is reportedly affected by a 
format string vulnerability."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 2.1.1p3 / 2.3.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  # http://lists.mindrot.org/pipermail/openssh-unix-dev/2004-November/022047.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4cd6ac9");
  # http://anoncvs.mindrot.org/index.cgi/openssh/ssh-keygen.c?r1=1.21&r2=1.22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95e39748");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2024 Tenable, Inc.");

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
  {'fixed_version': '2.1.1p3', 'fixed_display': '2.1.1p3 / 2.3.0'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
