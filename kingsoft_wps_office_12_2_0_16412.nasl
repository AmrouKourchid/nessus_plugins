#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206658);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id("CVE-2024-7262");
  script_xref(name:"IAVB", value:"2024-B-0129");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/24");

  script_name(english:"Kingsoft WPS Office 12.2.0.13110 < 12.2.0.16412 Arbitrary Code Execution (CVE-2024-7262)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Kingsoft WPS Office installed on the remote Windows host is at least 12.2.0.13110 and prior to
12.2.0.16412. It is, therefore, affected by an arbitrary code execution vulnerability:

  - Improper path validation in promecefpluginhost.exe in Kingsoft WPS Office version ranging from 12.2.0.13110 to
    12.2.0.16412 (exclusive) on Windows allows an attacker to load an arbitrary Windows library. The vulnerability was
    found weaponized as a single-click exploit in the form of a deceptive spreadsheet document. (CVE-2024-7262)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.welivesecurity.com/en/eset-research/analysis-of-two-arbitrary-code-execution-vulnerabilities-affecting-wps-office/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?224bde95");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kingsoft WPS Office 12.2.0.16412 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7262");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kingsoft:wps_office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kingsoft_wps_office_win_installed.nbin");
  script_require_keys("installed_sw/Kingsoft WPS Office", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Kingsoft WPS Office', win_local:TRUE);

var constraints = [
  { 'min_version':'12.2.0.13110', 'fixed_version' : '12.2.0.16412' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
