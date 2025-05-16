#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159491);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id(
    "CVE-2018-20685",
    "CVE-2019-6109",
    "CVE-2019-6110",
    "CVE-2019-6111"
  );

  script_name(english:"OpenSSH < 8.0");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote host is prior to 8.0. It is, therefore, affected
by the following vulnerabilities:

  - A permission bypass vulnerability due to improper directory name validation. An unauthenticated, remote
    attacker can exploit this, with a specially crafted scp server, to change the permission of a directory
    on the client. (CVE-2018-20685)

  - Multiple arbitrary file downloads due to improper validation of object name and stderr output. An unauthenticated
    remote attacker can exploit this, with a specially crafted scp server, to include additional hidden
    files in the transfer. (CVE-2019-6109, CVE-2019-6110)

  - An arbitrary file write vulnerability due to improper object name validation. An unauthenticated, remote
    attacker can exploit this, with a specially crafted scp server, to overwrite arbitrary files in the
    client directory. (CVE-2019-6111)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-8.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6111");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6110");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

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
  {'fixed_version' : '8.0'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
