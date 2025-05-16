#
# (C) Tenable, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#      Should also cover BugtraqID: 4560, BugtraqID: 4241/(CVE-2002-0083)
# 
# If the plugin is successful, it will issue a security_hole(). Should
# it attempt to determine if the remote host is a kerberos client and
# issue a security_warning() if it's not ?
#


include("compat.inc");

if(description)
{
 script_id(10802);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

 script_cve_id("CVE-2001-1507");
 script_bugtraq_id(3560);
 
 script_name(english:"OpenSSH < 3.0.1 Multiple Flaws");
 script_summary(english:"Checks for the remote SSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be
running OpenSSH version 3.0.1 or older. Such versions
are reportedly affected by multiple flaws :

  - Provided KerberosV is enabled (disabled by default),
    it may be possible for an attacker to partially
    authenticate.

  - It may be possible to crash the daemon due to a 
    excessive memory clearing bug.");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Nov/152");
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/11/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/19");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/11/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  {'fixed_version' : '3.0.1' }
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
