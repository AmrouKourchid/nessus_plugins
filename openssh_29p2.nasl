#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44071);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2001-0529");
  script_bugtraq_id(2825);

  script_name(english:"OpenSSH < 2.9.9 / 2.9p2 Symbolic Link 'cookies' File Removal");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:"Local attackers may be able to delete arbitrary files."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the banner, OpenSSH earlier than 2.9.9 / 2.9p2 is
running on the remote host. Such versions contain an arbitrary file
deletion vulnerability. Due to insecure handling of temporary files, a
local attacker can cause sshd to delete any file it can access named
'cookies'."
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 2.9p2 / 2.9.9 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-2.9.9");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-2.9p2");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/security.html");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/09/26");
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

var constraints = [
  {'fixed_version': '2.9p2', 'fixed_display': '2.9p2 / 2.9.9'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
