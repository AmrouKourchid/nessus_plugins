#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53841);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2011-4327");
  script_bugtraq_id(47691);
  script_xref(name:"Secunia", value:"44347");

  script_name(english:"Portable OpenSSH ssh-keysign ssh-rand-helper Utility File Descriptor Leak Local Information Disclosure");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:"Local attackers may be able to access sensitive information.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host is earlier than 5.8p2.  Such versions may be affected by a local
information disclosure vulnerability that could allow the contents of
the host's private key to be accessible by locally tracing the
execution of the ssh-keysign utility.  Having the host's private key
may allow the impersonation of the host. 

Note that installations are only vulnerable if ssh-rand-helper was
enabled during the build process, which is not the case for *BSD, OS
X, Cygwin and Linux."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Portable OpenSSH 5.8p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/portable-keysign-rand-helper.adv");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-5.8p2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"plugin_type", value:"remote");
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

# only affects portable OpenSSH
if (!app_info.portable)
  audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, app_info.version);

var constraints = [
  {'fixed_version': '5.8p2'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
