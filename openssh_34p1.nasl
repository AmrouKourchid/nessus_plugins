#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17701);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2004-0175");
  script_bugtraq_id(9986);

  script_name(english:"OpenSSH < 3.4p1 scp Traversal Arbitrary File Overwrite");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:
"A file transfer client on the remote host could be abused to
overwrite arbitrary files.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is earlier than version 3.4p1.  Such versions contain an
arbitrary file overwrite vulnerability that could allow a malicious
SSH server to cause the supplied scp utility to write to arbitrary
files outside of the current directory.");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 3.4p1 / 3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/support/security/alerts/adv59739.txt");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=120147");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cc380af");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssh_detect.nbin");
  script_require_keys("installed_sw/OpenSSH");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'fixed_version' : '3.4p1', 'fixed_display': '3.4p1 / 3.4'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
