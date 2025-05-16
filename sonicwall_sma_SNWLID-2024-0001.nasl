#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191467);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id("CVE-2024-22395");
  script_xref(name:"IAVA", value:"2024-A-0117-S");

  script_name(english:"SonicWall Secure Mobile Access < 10.2.1.11-65sv (SNWLID-2024-0001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of SonicWall Secure Mobile Access installed on the remote host is prior to 10.2.1.11-65sv. It is, therefore,
affected by a vulnerability as referenced in the SNWLID-2024-0001 advisory.

  - Improper access control vulnerability has been identified in the SMA100 SSL-VPN virtual office portal,
    which in specific conditions could potentially enable a remote authenticated attacker to associate another
    user's MFA mobile application. (CVE-2024-22395)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d5a41c2");
  script_set_attribute(attribute:"solution", value:
"Upgrade SonicWall Secure Mobile Access based upon the guidance specified in SNWLID-2024-0001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22395");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:sonicwall:firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'max_version' : '10.2.1.10.62', 'fixed_version' : '10.2.1.11.65', 'fixed_display' : '10.2.1.11-65sv' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
