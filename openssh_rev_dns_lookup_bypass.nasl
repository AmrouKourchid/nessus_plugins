#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11712);
 script_version("1.23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

 script_cve_id("CVE-2003-0386");
 script_bugtraq_id(7831);
 script_xref(name:"CERT", value:"978316");

 script_name(english:"OpenSSH < 3.6.2 Reverse DNS Lookup Bypass");
 script_summary(english:"Checks for the remote SSH version");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by DNS
lookup bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be running
OpenSSH-portable version 3.6.1 or older.

There is a flaw in such version that could allow an attacker to
bypass the access controls set by the administrator of this server.

OpenSSH features a mechanism that can restrict the list of
hosts a given user can log from by specifying a pattern
in the user key file (ie: *.mynetwork.com would let a user
connect only from the local network).

However there is a flaw in the way OpenSSH does reverse DNS lookups.
If an attacker configures a DNS server to send a numeric IP address
when a reverse lookup is performed, this mechanism could be
circumvented." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.6.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/05");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencie("openssh_detect.nbin");
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
  {'fixed_version' : '3.6.2' }
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
