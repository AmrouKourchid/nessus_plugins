#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232887);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id("CVE-2024-28989");
  script_xref(name:"IAVA", value:"2025-A-0192");

  script_name(english:"SolarWinds Web Help Desk < 12.8.5 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Solarwinds Web Help Desk installed on the remote host is prior to 12.8.5. It is, therefore, affected by
a vulnerability. SolarWinds Web Help Desk was found to have a hardcoded cryptographic key that could allow the disclosure of sensitive information from the software.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28989
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40e8daf2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Solarwinds Web Help Desk version 12.8.5 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28989");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:web_help_desk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_web_help_desk_detect.nbin", "solarwinds_web_help_desk_installed.nbin");
  script_require_keys("installed_sw/Solarwinds Web Help Desk");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Solarwinds Web Help Desk');

var constraints = [
  { 'fixed_version' : '12.8.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
