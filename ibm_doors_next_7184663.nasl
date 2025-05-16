#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227813);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/07");

  script_cve_id("CVE-2024-41770", "CVE-2024-41771");
  script_xref(name:"IAVA", value:"2025-A-0145");

  script_name(english:"IBM Engineering Requirements Management DOORS Next Temporary File Download / Archive File Download (7184663)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Engineering Requirements Management DOORS Next installed on the remote
host is 7.0.2 prior to 7.0.2 ifix 33 or 7.0.3 < 7.0.3 ifix 13 or 7.1.0 < 7.1.0 ifix 02. It is, therefore, affected 
by multiple vulnerabilities as referenced in the 7184663 advisory.

  - IBM Engineering Requirements Management DOORS Next could allow a remote attacker to download temporary 
    files which could expose application logic or other sensitive information. 
    (CVE-2024-41770, CVE-2024-41771)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7184663");
  script_set_attribute(attribute:"solution", value:
"Install 7.0.2 ifix 33 or 7.0.3 ifix 13 or 7.1.0 ifix 02 based upon the guidance specified in 7184663.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41770");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_doors");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_enum_products.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/IBM Engineering Requirements Management DOORS Next");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::ibm_doors_next::get_appinfo();

var constraints = [
  { 'min_version' : '7.0.2', 'fixed_version' : '7.0.2.33', 'fixed_display' : '7.0.2 iFix 33' },
  { 'min_version' : '7.0.3', 'fixed_version' : '7.0.3.13', 'fixed_display' : '7.0.3 iFix 13' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.0.2', 'fixed_display' : '7.1.0 iFix 02' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
