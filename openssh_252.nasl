#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44068);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2001-0361", "CVE-2001-0572");
  script_bugtraq_id(2344, 49473);
  script_xref(name:"CERT", value:"596827");

  script_name(english:"OpenSSH < 2.5.2 / 2.5.2p2 Multiple Information Disclosure Vulnerabilities");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Remote attackers may be able to infer information about traffic
inside an SSH session."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote host appears to be running a
version of OpenSSH earlier than 2.5.2 / 2.5.2p2. It, therefore,
reportedly contains weaknesses in its implementation of the SSH
protocol, both versions 1 and 2.  These weaknesses could allow an
attacker to sniff password lengths, and ranges of length (this could
make brute-force password guessing easier), determine whether RSA or
DSA authentication is being used, the number of authorized_keys in RSA
authentication and/or the length of shell commands."
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 2.5.2 / 2.5.2p2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/articles/SSH-Traffic-Analysis");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-2.5.2p2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

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

var constraints = NULL;

if (!app_info.portable)
  constraints = [{'fixed_version': '2.5.2'}];
else
  constraints = [{'fixed_version': '2.5.2p2'}];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
