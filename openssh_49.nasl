#
# (C) Tenable, Inc.
#


include("compat.inc");

if (description)
{
  script_id(44079);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2008-1657");
  script_bugtraq_id(28531);

  script_name(english:"OpenSSH < 4.9 'ForceCommand' Directive Bypass");
  script_summary(english:"Checks OpenSSH server version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH installed on the
remote host is earlier than 4.9.  It may allow a remote, authenticated
user to bypass the 'sshd_config' 'ForceCommand' directive by modifying
the '.ssh/rc' session file.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-4.9");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH version 4.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

  script_set_attribute(attribute:"plugin_type", value: "remote");
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
  {'fixed_version': '4.9'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
