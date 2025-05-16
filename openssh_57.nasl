#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44081);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2010-4478", "CVE-2012-0814");
  script_bugtraq_id(45304, 51702);

  script_name(english:"OpenSSH < 5.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service may be affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is earlier than 5.7.  Versions before 5.7 may be affected by the 
following vulnerabilities :

  - A security bypass vulnerability because OpenSSH does not 
    properly validate the public parameters in the J-PAKE
    protocol.  This could allow an attacker to authenticate 
    without the shared secret.  Note that this issue is only
    exploitable when OpenSSH is built with J-PAKE support,
    which is currently experimental and disabled by default, 
    and that Nessus has not checked whether J-PAKE support
    is indeed enabled. (CVE-2010-4478)

  - The auth_parse_options function in auth-options.c in 
    sshd provides debug messages containing authorized_keys
    command options, which allows remote, authenticated 
    users to obtain potentially sensitive information by 
    reading these messages. (CVE-2012-0814)");

  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 5.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4478");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://seb.dbzteam.org/crypto/jpake-session-key-retrieval.pdf");
  script_set_attribute(attribute:"see_also", value:"http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/Attic/jpake.c#rev1.5");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ac4f8d9");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"plugin_type", value:"remote");
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
  {'fixed_version': '5.7'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
