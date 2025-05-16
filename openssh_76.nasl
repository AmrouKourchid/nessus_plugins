#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103781);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2017-15906");
  script_bugtraq_id(101552);

  script_name(english:"OpenSSH < 7.6");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a 
file creation restriction bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.6. It is, therefore, affected by a file creation
restriction bypass vulnerability related to the 'process_open'
function in the file 'sftp-server.c' that allows authenticated users
to create zero-length files regardless of configuration.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://github.com/openbsd/src/commit/a6981567e8e215acc1ef690c8dbb30f2d9b00a19#diff-8b99aa649abd796be7cc465d6f0a2f96
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09ca048b");
  # https://github.com/openssh/openssh-portable/commit/4d827f0d75a53d3952288ab882efbddea7ffadfe#diff-066c02faff81900a14a658dae29b3e15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96a8ea52");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");

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
  {'fixed_version': '7.6'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
