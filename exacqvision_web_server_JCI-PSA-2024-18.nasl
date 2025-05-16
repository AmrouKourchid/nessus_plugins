#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205317);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/26");

  script_cve_id("CVE-2024-32865");
  script_xref(name:"IAVB", value:"2024-B-0104");
  script_xref(name:"ICSA", value:"24-214-05");

  script_name(english:"Johnson Controls ExacqVision Web Server < 24.04 Improper Certificate Validation (JCI-PSA-2024-18)");

  script_set_attribute(attribute:"synopsis", value:
"A web server running on the remote host is affected by a certificate validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Johnson Controls exacqVision Web Server running on the remote host is prior to 24.04. It is, 
therefore, affected by a certificate validation vulnerability. Under certain circumstances the exacqVision Server will 
not properly validate TLS certificates provided by connected devices.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?add56de2");
  # https://www.johnsoncontrols.com/-/media/project/jci-global/johnson-controls/us-region/united-states-johnson-controls/cyber-solutions/security-advisories/documents/jci-psa-2024-18.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c3d6654");
  script_set_attribute(attribute:"solution", value:
"Upgrade exacqVision Web Service to version 24.06 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32865");

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
  {'max_version': '24.3', 'fixed_version': '24.6'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);