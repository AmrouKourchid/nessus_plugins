#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84638);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2015-5352");
  script_bugtraq_id(75525);

  script_name(english:"OpenSSH < 6.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 6.9. It is, therefore, affected by the following
vulnerabilities :

  - A flaw exists within the x11_open_helper() function in
    the 'channels.c' file that allows connections to be
    permitted after 'ForwardX11Timeout' has expired. A
    remote attacker can exploit this to bypass timeout
    checks and XSECURITY restrictions. (CVE-2015-5352)

  - Various issues were addressed by fixing the weakness in
    agent locking by increasing the failure delay, storing
    the salted hash of the password, and using a timing-safe
    comparison function.

  - An out-of-bounds read error exists when handling
    incorrect pattern lengths. A remote attacker can exploit
    this to cause a denial of service or disclose sensitive
    information in the memory.

  - An out-of-bounds read error exists when parsing the
    'EscapeChar' configuration option.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-6.9");
  # https://anongit.mindrot.org/openssh.git/commit/?id=77199d6ec8986d470487e66f8ea8f4cf43d2e20c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?725c4682");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 6.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");

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
  {'fixed_version': '6.9'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
