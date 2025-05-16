#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44080);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2008-3259");
  script_bugtraq_id(30339);

  script_name(english:"OpenSSH X11UseLocalhost X11 Forwarding Port Hijacking");
  script_summary(english:"Checks OpenSSH server version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service may be affected by an X11 forwarding port
hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of SSH installed on the remote
host is older than 5.1 and may allow a local user to hijack the X11
forwarding port.  The application improperly sets the 'SO_REUSEADDR'
socket option when the 'X11UseLocalhost' configuration option is
disabled.

Note that most operating systems, when attempting to bind to a port
that has previously been bound with the 'SO_REUSEADDR' option, will
check that either the effective user-id matches the previous bind
(common BSD-derived systems) or that the bind addresses do not overlap
(Linux and Solaris).  This is not the case with other operating
systems such as HP-UX.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-5.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH version 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/21");
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
  {'fixed_version': '5.1'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
