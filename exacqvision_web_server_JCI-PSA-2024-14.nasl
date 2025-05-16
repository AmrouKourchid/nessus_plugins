#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205316);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/26");

  script_cve_id("CVE-2024-32758");
  script_xref(name:"IAVB", value:"2024-B-0104");
  script_xref(name:"ICSA", value:"24-214-01");

  script_name(english:"Johnson Controls ExacqVision Web Server Inadequate Encryption Strength (JCI-PSA-2024-14)");

  script_set_attribute(attribute:"synopsis", value:
"A web server running on the remote host is affected by an inadequate encryption strength vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Johnson Controls exacqVision Web Server running on the remote host is affected by an inadequate 
encryption strength vulnerability. Under certain circumstances the communication between exacqVision Client and
exacqVision Server will use insufficient key length and exchange.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?add56de2");
  # https://www.johnsoncontrols.com/-/media/project/jci-global/johnson-controls/us-region/united-states-johnson-controls/cyber-solutions/security-advisories/documents/jci-psa-2024-14.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d26e725d");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:johnsoncontrols:exacqvision_web_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SCADA");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("exacqvision_web_server_win_installed.nbin", "johnson_controls_exacqvision_web_server_nix_installed.nbin");
  script_require_keys("installed_sw/Johnson Controls ExacqVision Web Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Johnson Controls ExacqVision Web Server');

var constraints = [
  {'fixed_version': '999999', 'fixed_display': 'See vendor advisory'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);