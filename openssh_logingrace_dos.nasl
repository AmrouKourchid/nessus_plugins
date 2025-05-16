#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67140);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2010-5107");
  script_bugtraq_id(58162);

  script_name(english:"OpenSSH LoginGraceTime / MaxStartups DoS");
  script_summary(english:"Checks OpenSSH banner version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is susceptible to a remote denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, a version of OpenSSH earlier than version 6.2
is listening on this port.  The default configuration of OpenSSH
installs before 6.2 could allow a remote attacker to bypass the
LoginGraceTime and MaxStartups thresholds by periodically making a large
number of new TCP connections and thereby prevent legitimate users from
gaining access to the service. 

Note that this plugin has not tried to exploit the issue or detect
whether the remote service uses a vulnerable configuration.  Instead, it
has simply checked the version of OpenSSH running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2013/02/06/5");
  script_set_attribute(attribute:"see_also", value:"http://openssh.org/txt/release-6.2");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=28883");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 6.2 and review the associated server configuration
settings.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'fixed_version' : '6.2'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
