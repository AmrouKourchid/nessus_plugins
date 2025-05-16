#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78655);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2014-2653");
  script_bugtraq_id(66459);

  script_name(english:"OpenSSH SSHFP Record Verification Weakness");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:
"A secure shell client on the remote host could be used to bypass host
verification methods.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is 6.1 through 6.6.

It is, therefore, affected by a host verification bypass vulnerability
related to SSHFP and certificates that could allow a malicious SSH
server to cause the supplied client to inappropriately trust the
server.");
  # Vendor patch and note
  script_set_attribute(attribute:"see_also", value:"http://thread.gmane.org/gmane.network.openssh.devel/20679");
  # SSHFP RFC "Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints"
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc4255");
  # CVE assignment
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2014/q1/663");
  script_set_attribute(attribute:"solution", value:"Update to OpenSSH version 6.7 or later or apply the vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2653");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");

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
  {'min_version': '6.1', 'fixed_version': '6.7'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
