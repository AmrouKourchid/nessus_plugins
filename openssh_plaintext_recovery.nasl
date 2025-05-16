#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44065);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2008-5161");
  script_bugtraq_id(32319);
  script_xref(name:"CERT", value:"958563");

  script_name(english:"OpenSSH < 5.2 CBC Plaintext Disclosure");
  script_summary(english:"Checks SSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH service running on the remote host has an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of OpenSSH running on the remote host has an information
disclosure vulnerability.  A design flaw in the SSH specification
could allow a man-in-the-middle attacker to recover up to 32 bits of
plaintext from an SSH-protected connection in the standard
configuration.  An attacker could exploit this to gain access to
sensitive information."
  );
  # http://web.archive.org/web/20090523091544/http://www.cpni.gov.uk/docs/vulnerability_advisory_ssh.txt
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?4984aeb9");
  script_set_attribute(attribute:"see_also",value:"http://www.openssh.com/txt/cbc.adv");
  script_set_attribute(attribute:"see_also",value:"http://www.openssh.com/txt/release-5.2");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 5.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/27");

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
  {'fixed_version' : '5.2' }
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

