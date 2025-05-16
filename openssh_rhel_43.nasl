#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17706);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2009-2904");
  script_bugtraq_id(36552);
  script_xref(name:"RHSA", value:"2009:1470");

  script_name(english:"Red Hat Enterprise Linux OpenSSH ChrootDirectory Local Privilege Escalation");
  script_summary(english:"Checks OpenSSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server running on the remote host has a privilege escalation
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host may have a privilege escalation vulnerability.  OpenSSH on Red
Hat Enterprise Linux 5, Fedora 11, and possibly other platforms use an
insecure implementation of the 'ChrootDirectory' configuration
setting, which could allow privilege escalation.  Upstream OpenSSH is
not affected. 

The fix for this issue does not change the version in the OpenSSH
banner, so this may be a false positive."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=522141");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate patch listed in Red Hat security advisory
RHSA-2009:1470-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(16);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssh_detect.nbin");
  script_require_keys("installed_sw/OpenSSH", "Settings/PCI_DSS");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

# Only RHEL and FC packages are affected
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port, skip_upgrade:TRUE);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'equal': '4.3', 'fixed_display' : 'See vendor advisory'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
