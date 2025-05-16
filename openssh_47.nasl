#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44078);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2007-4752", "CVE-2007-2243");
  script_bugtraq_id(25628);

  script_name(english:"OpenSSH < 4.7 Trusted X11 Cookie Connection Policy Bypass");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:"Remote attackers may be able to bypass authentication."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the banner, OpenSSH earlier than 4.7 is running on the
remote host.  Such versions contain an authentication bypass
vulnerability.  In the event that OpenSSH cannot create an untrusted
cookie for X, for example due to the temporary partition being full,
it will use a trusted cookie instead.  This allows attackers to
violate intended policy and gain privileges by causing their X client
to be treated as trusted."
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 4.7 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 287);

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssh.com/txt/release-4.7"
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

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
  {'fixed_version': '4.7'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
