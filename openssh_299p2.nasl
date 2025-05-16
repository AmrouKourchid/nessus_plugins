#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44070);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2001-1382");

  script_name(english:"OpenSSH < 2.9.9p2 echo simulation Information Disclosure");
  script_summary(english:"Checks for remote SSH version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by an information disclosure
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSH earlier than 2.9.9p2.  It therefore can potentially disclose
the fact that the 'echo simulation' countermeasure is in use because
the application sends an additional echo packet after the password and
carriage return is entered. 

Note that this issue only exists when the 'echo simulation'
countermeasure is enabled.");

  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 2.9.9p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  {'fixed_version' : '2.9.9p2', 'fixed_display': '2.9.9p2 / 3.0'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
