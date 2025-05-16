#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186699);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/23");

  script_cve_id("CVE-2023-41265", "CVE-2023-41266");
  script_xref(name:"IAVA", value:"2023-A-0665");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/28");

  script_name(english:"Qlik Sense Enterprise Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A data analytics server installed on the remote Windows host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Qlik Sense Enterprise installed on the remote Windows host is prior August 2022 Patch 14, November 2022
prior to Patch 11, February 2023 prior to Patch 8 or May 2023 prior to Patch 4. It is, therefore, affected by multiple
vulnerabilities.

 - An HTTP tunneling vulnerability due to improper validation of HTTP headers. A remote attacker is able to
   elevate their privilege by tunneling HTTP requests, allowing them to execute HTTP requests on the backend
   server hosting the repository application. (CVE-2023-41265)

 - A path traversal vulnerability due to improper validation of user-supplied input. An unauthenticated,
   remote attacker can generate an anonymous session which allows them to perform HTTP requests to
   unauthorized endpoints. (CVE-2023-41266)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.qlik.com/t5/Official-Support-Articles/Critical-Security-fixes-for-Qlik-Sense-Enterprise-for-Windows/ta-p/2110801
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd7d0674");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Qlik Sense Enterprise in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41265");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qlik:qlik_sense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qlik_sense_enterprise_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Qlik Sense Enterprise");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Qlik Sense Enterprise', win_local:TRUE);

var constraints = [
  # Version information taken from https://github.com/qlik-download/qlik-sense-server/releases
  { 'fixed_version' : '14.44.26', 'fixed_display': 'November 2021 Patch 17 (14.44.26)' },
  { 'min_version': '14.54.2', 'fixed_version' : '14.54.24', 'fixed_display': 'February 2022 Patch 15 (14.54.24)' },
  { 'min_version': '14.67.7', 'fixed_version' : '14.67.29', 'fixed_display': 'May 2022 Patch 16 (14.67.29)' },
  { 'min_version': '14.78.5', 'fixed_version' : '14.78.20', 'fixed_display': 'August 2022 Patch 13 (14.78.20)' },
  { 'min_version': '14.97.3', 'fixed_version' : '14.97.16', 'fixed_display': 'November 2022 Patch 11 (14.97.16)' },
  { 'min_version': '14.113.2', 'fixed_version' : '14.113.11', 'fixed_display': 'February 2023 Patch 8 (14.113.11)' },
  { 'min_version': '14.129.6', 'fixed_version' : '14.129.10', 'fixed_display': 'May 2023 Patch 4 (14.129.10)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
