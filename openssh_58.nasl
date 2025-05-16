#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51920);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2011-0539");
  script_bugtraq_id(46155);
  script_xref(name:"Secunia", value:"43181");

  script_name(english:"OpenSSH Legacy Certificate Signing Information Disclosure");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:"Remote attackers may be able to access sensitive information."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the banner, OpenSSH 5.6 or 5.7 is running on the remote
host. These versions contain an information disclosure vulnerability.
This vulnerability may cause the contents of the stack to be copied
into an SSH certificate, which is visible to a remote attacker. This
information may lead to further attacks."
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 5.8 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssh.com/txt/legacy-cert.adv"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssh.com/txt/release-5.8"
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
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

var constraints = [
  {'min_version': '5.6', 'fixed_version': '5.8'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
