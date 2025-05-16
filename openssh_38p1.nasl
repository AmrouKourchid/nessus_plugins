#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44074);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2004-2069");
  script_bugtraq_id(9040, 14963);

  script_name(english:"Portable OpenSSH < 3.8p1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Remote attackers may be able to cause information to leak from
aborted sessions."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, a version of OpenSSH earlier than 3.8p1 is
running on the remote host and is affected by the following issues:

  - There is an issue in the handling of PAM modules in 
    such versions of OpenSSH.  As a result, OpenSSH may not
    correctly handle aborted conversations with PAM modules. 
    Consequently, that memory may not be scrubbed of 
    sensitive information such as credentials, which could 
    lead to credentials leaking into swap space and core 
    dumps.  Other vulnerabilities in PAM modules could come
    to light because of unpredictable behavior.

  - Denial of service attacks are possible when privilege
    separation is in use. This version of OpenSSH does not
    properly signal non-privileged processes after session
    termination when 'LoginGraceTime' is exceeded. This can
    allow connections to remain open thereby allowing the 
    denial of service when resources are exhausted. 
    (CVE-2004-2069)

");

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 3.8p1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"https://www.cl.cam.ac.uk/~mgk25/otpw.html#opensshbug");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mindrot.org/show_bug.cgi?id=632");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e86aec66");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbd79dfd");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2f25e5c");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/17");
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

# OpenBSD does not use PAM, so this vulnerability only exists in the
# portable version of OpenSSH.
if (!app_info.portable)
  audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, app_info.version);

var constraints = [
  {'fixed_version': '3.8p1'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);