#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44067);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2000-0217");
  script_bugtraq_id(1006);

  script_name(english:"OpenSSH < 1.2.3 xauth Session Highjacking");
  script_summary(english:"Checks for remote SSH version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
session highjacking vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSH earlier than 1.2.3.  Such versions are affected by a session
highjacking vulnerability.  By default, ssh clients negotiate to
forward X connections by using the xauth program to place cookies in
the authorization cache of the remote machine for the user that is
logging in.  It is possible for the xauth key to be read from the
user's .Xauthority file which could allow a remote attacker to control
the client's X sessions via a malicious xauth program.");

  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-1.2.3p1");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/security.html");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=95151911210810&w=4");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 1.2.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/03/17");
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
  {'fixed_version': '1.2.3'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
