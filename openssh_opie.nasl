#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(17705);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2007-2768");

  script_name(english:"OPIE w/ OpenSSH Account Enumeration");
  script_summary(english:"Checks if OpenSSH is installed");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is susceptible to an information disclosure attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"When using OPIE for PAM and OpenSSH, it is possible for remote
attackers to determine the existence of certain user accounts. 

Note that Nessus has not tried to exploit the issue, but rather only
checked if OpenSSH is running on the remote host.  As a result, it
does not detect if the remote host actually has OPIE for PAM
installed."
  );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2007/Apr/634");
  script_set_attribute(
    attribute:"solution",
    value:
"A patch currently does not exist for this issue. As a workaround,
ensure that OPIE for PAM is not installed."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/21");
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

if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'fixed_display' : 'See vendor advisory'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
