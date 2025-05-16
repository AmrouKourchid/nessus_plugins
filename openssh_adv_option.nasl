#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10771);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2001-0816", "CVE-2001-1380");
  script_bugtraq_id(3345, 3369);
  script_xref(name:"CERT", value:"905795");

  script_name(english:"OpenSSH 2.5.x - 2.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote version of OpenSSH contains multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be running
OpenSSH version between 2.5.x and 2.9.  Such versions reportedly
contain multiple vulnerabilities :

  - sftp-server does not respect the 'command=' argument of
    keys in the authorized_keys2 file. (CVE-2001-0816)

  - sshd does not properly handle the 'from=' argument of 
    keys in the authorized_keys2 file. If a key of one type 
    (e.g. RSA) is followed by a key of another type (e.g. 
    DSA) then the options for the latter will be applied to
    the former, including 'from=' restrictions. This problem
    allows users to circumvent the system policy and login
    from disallowed source IP addresses. (CVE-2001-1380)");

  script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/advisories/ssh_option.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?759da6a7");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-2.9.9");

  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 2.9.9" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/09/28");

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
  {'min_version': '2.5', 'fixed_version' : '2.9.9' }
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
