#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44077);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2006-4925", "CVE-2006-5794", "CVE-2007-0726");
  script_bugtraq_id(20956);

  script_name(english:"OpenSSH < 4.5 Multiple Vulnerabilities");
  script_summary(english:"Checks for remote SSH version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSH prior to 4.5.  Versions before 4.5 are affected by the
following vulnerabilities :

  - A client-side NULL pointer dereference, caused by a
    protocol error from a malicious server, which could
    cause the client to crash. (CVE-2006-4925)

  - A privilege separation vulnerability exists, which could 
    allow attackers to bypass authentication. The 
    vulnerability is caused by a design error between 
    privileged processes and their child processes. Note 
    that this particular issue is only exploitable when 
    other vulnerabilities are present. (CVE-2006-5794)

  - An attacker that connects to the service before it has 
    finished creating keys could force the keys to be 
    recreated. This could result in a denial of service for 
    any processes that relies on a trust relationship with 
    the server. Note that this particular issue only affects 
    the Apple implementation of OpenSSH on Mac OS X. 
    (CVE-2007-0726)"
  );

  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-4.5");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/kb/TA24626?locale=en_US");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 4.5 or later.
For Mac OS X 10.3, apply Security Update 2007-003.
For Mac OS X 10.4, upgrade to 10.4.9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable, Inc.");
  script_family(english:"Misc.");

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
  {'fixed_version': '4.5'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
