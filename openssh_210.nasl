#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17700);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2000-0535");
  script_bugtraq_id(1340);

  script_name(english:"OpenSSH < 2.1.0 /dev/random Check Failure");
  script_summary(english:"Checks the version of OpenSSH");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of SSH that may have weak
encryption keys.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is less than 2.1.0. On a FreeBSD system running on the Alpha
architecture, versions earlier than that may not use the /dev/random
and /dev/urandom devices to provide a strong source of cryptographic
entropy, which could lead to the generation of keys with weak
cryptographic strength.");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/fileview?f=openssl/CHANGES&v=1.514");
  # https://web.archive.org/web/20000819114726/http://archives.neohapsis.com/archives/freebsd/2000-06/0083.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16bc8320");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dca3a5e9");
  script_set_attribute(attribute:"solution", value:
"Upgrade OpenSSH to version 2.1.0 or higher / OpenSSL to version 0.9.5a
or higher and re-generate encryption keys.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

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
  {'fixed_version': '2.1.0'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
