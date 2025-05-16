#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99359);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");


  script_name(english:"OpenSSH < 7.5 ");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by an 
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.5. It is, therefore, affected by an information disclosure
vulnerability :

  - An unspecified timing flaw exists in the CBC padding
    oracle countermeasures, within the ssh and sshd
    functions, that allows an unauthenticated, remote
    attacker to disclose potentially sensitive information.
    Note that the OpenSSH client disables CBC ciphers by
    default. However, sshd offers them as lowest-preference
    options, which will be removed by default in a future
    release.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

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
  {'fixed_version' : '7.5'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
