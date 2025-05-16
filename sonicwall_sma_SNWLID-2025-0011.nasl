#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235656);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2025-32819",
    "CVE-2025-32820",
    "CVE-2025-32821"
  );
  script_xref(name:"IAVA", value:"2025-A-0319");

  script_name(english:"SonicWall Secure Mobile Access < 10.2.1.15-81sv (SNWLID-2025-0011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of SonicWall Secure Mobile Access installed on the remote host is prior to 10.2.1.15-81sv. It is, therefore,
affected by multiple vulnerabilities as referenced in the SNWLID-2025-0011 advisory:

  - A vulnerability in SMA100 allows a remote authenticated attacker with SSLVPN user privileges to bypass the path
    traversal checks and delete an arbitrary file potentially resulting in a reboot to factory default settings.
    (CVE-2025-32819)

  - A vulnerability in SMA100 allows a remote authenticated attacker with SSLVPN user privileges can inject a path
    traversal sequence to make any directory on the SMA appliance writable. (CVE-2025-32820)

  - A vulnerability in SMA100 allows a remote authenticated attacker with SSLVPN admin privileges can with admin
    privileges can inject shell command arguments to upload a file on the appliance. (CVE-2025-32821)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73dcef8b");
  script_set_attribute(attribute:"solution", value:
"Upgrade SonicWall Secure Mobile Access version 10.2.1.15-81sv or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32819");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:sonicwall:firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sma_web_detect.nbin");
  script_require_keys("installed_sw/SonicWall Secure Mobile Access", "Settings/ParanoidReport");

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app_name = 'SonicWall Secure Mobile Access';

get_install_count(app_name:app_name, exit_if_zero:TRUE);

# We cannot test for vulnerable models
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var port = get_http_port(default:443, embedded:TRUE);

var app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

var constraints = [
  { 'max_version' : '10.2.1.14.75', 'fixed_version' : '10.2.1.15.81', 'fixed_display' : '10.2.1.15-81sv' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
