#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214591);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2025-23006");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/14");
  script_xref(name:"IAVA", value:"2025-A-0076-S");

  script_name(english:"SonicWall SMA 1000 Series < 12.4.3-02854 Pre-authentication Remote Command Execution (SNWLID-2025-0002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a pre-authentication remote command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a SonicWall SMA 1000 Series device that may be affected by a pre-authentication remote command
execution vulnerability:

  - Pre-authentication deserialization of untrusted data vulnerability has been identified in the SMA1000 Appliance
    Management Console (AMC) and Central Management Console (CMC), which in specific conditions could potentially
    enable a remote unauthenticated attacker to execute arbitrary OS commands. (CVE-2025-23006)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa63681d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SonicWall SMA 1000 Series version 12.4.3-02854 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23006");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:sonicwall:firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sma_web_detect.nbin");
  script_require_keys("installed_sw/SonicWall Secure Mobile Access", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app_name = 'SonicWall Secure Mobile Access';
var fix = '12.4.3.02854';

get_install_count(app_name:app_name, exit_if_zero:TRUE);

var port = get_http_port(default:443, embedded:TRUE);

var app_info = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:FALSE);

app_info.port = port;
app_info.app = app_name;

if (empty_or_null(app_info.Series))
  app_info.Series = UNKNOWN_VER;

if (app_info.version != UNKNOWN_VER)
  app_info.parsed_version = vcf::parse_version(app_info.version);

if (app_info.Series != '1000' && app_info.Series != UNKNOWN_VER)
  audit(AUDIT_HOST_NOT, "a SMA 1000 Series device");

var constraints = [{'fixed_version' : fix}];

if (app_info.version == UNKNOWN_VER)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
    
  vcf::report_results(
    app_info:app_info,
    fix:fix,
    severity:SECURITY_HOLE
  );
  exit(0);
}

if (app_info.Series == '1000')
{
  if (ver_compare(ver:app_info.version, fix:'12.4') < 0 ||
      ver_compare(ver:app_info.version, fix:'12.5') >= 0)
  {
    vcf::check_version_and_report(
      app_info:app_info,
      constraints:constraints,
      severity:SECURITY_HOLE
    );
    exit(0);
  }
  else
  {
    if (app_info.version == '12.4')
    {
      if (report_paranoia < 2)
       audit(AUDIT_PARANOID);
    }

    vcf::check_version_and_report(
      app_info:app_info,
      constraints:constraints,
      severity:SECURITY_HOLE
    );
    exit(0);
  }
}
else if (app_info.Series == UNKNOWN_VER)
{
  if (ver_compare(ver:app_info.version, fix:'12.5') >= 0)
  {
    vcf::check_version_and_report(
      app_info:app_info,
      constraints:constraints,
      severity:SECURITY_HOLE
    );
    exit(0);
  }
  else
  {
    if (report_paranoia < 2)
      audit(AUDIT_PARANOID);

    vcf::check_version_and_report(
      app_info:app_info,
      constraints:constraints,
      severity:SECURITY_HOLE
    );
    exit(0);
  }
}