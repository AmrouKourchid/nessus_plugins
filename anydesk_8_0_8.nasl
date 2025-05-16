#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189954);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_name(english:"AnyDesk < 8.0.8 Invalidated Signing Certificate");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A security update as been issued by the vendor advising their code signing certificate has changed on product versions
less than 8.0.8. The vendor recommends updating to the latest version as the previous certificate will soon be
invalidated.");
  script_set_attribute(attribute:"see_also", value:"https://anydesk.com/en/faq-incident");
  script_set_attribute(attribute:"see_also", value:"https://anydesk.com/en/public-statement");
  script_set_attribute(attribute:"see_also", value:"https://anydesk.com/en/changelog/windows");
  script_set_attribute(attribute:"solution", value:
"Update the affected AnyDesk package.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:anydesk:anydesk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("anydesk_win_installed.nbin");
  script_require_keys("installed_sw/AnyDesk");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'AnyDesk');

var constraints = [
  {'fixed_version' : '7.0.15'},
  {'min_version' : '8.0', 'fixed_version' : '8.0.8'}
];

var matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints);
var vuln = 0;
var report;

if(!vcf::is_error(matching_constraint) && !isnull(matching_constraint))
{
  vuln++;
  report +=
    '  Installed Version  : ' + app_info.version + '\n' + 
    '  Fixed Version      : ' + matching_constraint.fixed_version + '\n';
}

var revoked_cert_issuer = 'DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1';
var revoked_cert_serial = '0dbf152deaf0b981a8a938d53f769db8';
var found_issuer = app_info['Certificate Issuer'];
var found_serial = app_info['Certificate SerialNumber'];
var cert_info = 'Nessus was unable to check the certificate used by the application.';
if (!empty_or_null(found_issuer) && !empty_or_null(found_serial))
{
  if (!vuln)
    report += '  Installed Version  : ' + app_info.version + '\n';
  
  cert_info = '  Certificate Serial : ' + found_serial + '\n';
  if (tolower(revoked_cert_issuer) >< tolower(found_issuer) &&
      tolower(found_serial) == tolower(revoked_cert_serial))
  {
    cert_info += '\nNessus was able to determine that the application uses the affected certificate.';
    vuln++;
  }
  else
    cert_info += '\nNessus was able to determine that the application does not use the affected certificate.';
  
}
report += cert_info;

if(!vuln) audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(port:445, severity:SECURITY_NOTE, extra:report);
