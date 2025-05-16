#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93194);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2015-8325", "CVE-2016-6515", "CVE-2016-6210");
  script_bugtraq_id(86187, 92212);

  script_name(english:"OpenSSH < 7.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.3. It is, therefore, affected by multiple
vulnerabilities :

  - A local privilege escalation when the UseLogin feature
    is enabled and PAM is configured to read .pam_environment
    files from home directories. (CVE-2015-8325)

  - A flaw exists that is due to the program returning
    shorter response times for authentication requests with
    overly long passwords for invalid users than for valid
    users. This may allow a remote attacker to conduct a
    timing attack and enumerate valid usernames.
    (CVE-2016-6210)

  - A denial of service vulnerability exists in the
    auth_password() function in auth-passwd.c due to a
    failure to limit password lengths for password
    authentication. An unauthenticated, remote attacker can
    exploit this, via a long string, to consume excessive
    CPU resources, resulting in a denial of service
    condition. (CVE-2016-6515)

  - An unspecified flaw exists in the CBC padding oracle
    countermeasures that allows an unauthenticated, remote
    attacker to conduct a timing attack.

  - A flaw exists due to improper operation ordering of MAC
    verification for Encrypt-then-MAC (EtM) mode transport
    MAC algorithms when verifying the MAC before decrypting
    any ciphertext. An unauthenticated, remote attacker can
    exploit this, via a timing attack, to disclose sensitive
    information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.3");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=openbsd-announce&m=147005433429403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6515");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

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
  {'fixed_version' : '7.3' }
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
