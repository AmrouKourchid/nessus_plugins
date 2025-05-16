#
# (C) Tenable, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44073);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2006-0883");
  script_bugtraq_id(16892);

  script_name(english:"OpenSSH With OpenPAM DoS");
  script_summary(english:"Checks SSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server running on the remote host has a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host is affected by a remote denial of service vulnerability. When
used with OpenPAM, OpenSSH does not properly handle when a forked
child process ends during PAM authentication. This could allow a
remote attacker to cause a denial of service by connecting several
times to the SSH server, waiting for the password prompt and then
disconnecting."
  );
  script_set_attribute(attribute:"see_also",value:"https://bugzilla.mindrot.org/show_bug.cgi?id=839");
  # ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-06:09.openssh.asc
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?170f19e3");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 3.8.1p1 / 3.9 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

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
  {'fixed_version' : '3.8.1p1', 'fixed_display': '3.8.1p1 / 3.9'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
