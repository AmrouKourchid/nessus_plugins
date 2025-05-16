#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17703);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2010-4755","CVE-2011-5000");
  script_bugtraq_id(54114, 68757);

  script_name(english:"OpenSSH < 5.9 Multiple DoS");
  script_summary(english:"Checks OpenSSH banner version");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server on the remote host has multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to version 5.9. Such versions are affected by multiple
denial of service vulnerabilities :

  - A denial of service vulnerability exists in the
    gss-serv.c 'ssh_gssapi_parse_ename' function.  A remote
    attacker may be able to trigger this vulnerability if
    gssapi-with-mic is enabled to create a denial of service
    condition via a large value in a certain length field.
    (CVE-2011-5000)

  - On FreeBSD, NetBSD, OpenBSD, and other products, a
    remote, authenticated attacker could exploit the
    remote_glob() and process_put() functions to cause a
    denial of service (CPU and memory consumption).
    (CVE-2010-4755)");
  script_set_attribute(attribute:"see_also", value:"http://cxsecurity.com/research/89");
  script_set_attribute(attribute:"see_also",value:"http://site.pi3.com.pl/adv/ssh_1.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 5.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssh_detect.nbin");
  script_require_keys("installed_sw/OpenSSH", "Settings/PCI_DSS");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

# OpenSSH is only affected on certain OSes.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'fixed_version' : '5.9'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
