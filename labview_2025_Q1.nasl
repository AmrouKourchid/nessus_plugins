#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234623);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2025-2629",
    "CVE-2025-2630",
    "CVE-2025-2631",
    "CVE-2025-2632"
    );
    script_xref(name:"IAVA", value:"2025-A-0259");

  script_name(english:"National Instruments LabVIEW < 2025 Q1 Multiple Vulnerabilities (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of National Instruments (NI) LabVIEW installed on the remote Windows host is affected by multiple
vulnerabilities:

  - There are two out of bounds write vulnerabilities due to improper bounds checking that exist in NI LabVIEW 
    that may result in information disclosure or arbitrary code execution. Successful exploitation requires 
    an attacker to get a user to open a specially crafted VI. These vulnerabilities affect NI LabVIEW 2025 
    Q1 and prior versions. (CVE-2025-2631, CVE-2025-2632)

  - There is a DLL hijacking vulnerability due to an uncontrolled search path that exists in NI LabVIEW. This 
    vulnerability may result in arbitrary code execution. Successful exploitation requires an attacker to 
    insert a malicious DLL into the uncontrolled search path. This vulnerability affects NI LabVIEW 2025 Q1 
    and prior versions. (CVE-2025-2630)

  - There is a DLL hijacking vulnerability due to an uncontrolled search path that exists in NI LabVIEW when 
    loading NI Error Reporting. This vulnerability may result in arbitrary code execution. Successful 
    exploitation requires an attacker to insert a malicious DLL into the uncontrolled search path. This 
    vulnerability affects NI LabVIEW 2025 Q1 and prior versions. (CVE-2025-2629)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software.html#section--1834566742
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?405f14bc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the NI LabVIEW version referenced in the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2632");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ni:labview");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("labview_installed.nbin");
  script_require_keys("installed_sw/National Instruments LabVIEW", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'National Instruments LabVIEW');

var constraints = [
  { 'min_version':'2025.0', 'fixed_version' : '2025.1.2', 'fixed_display' : '2025 Q1 Patch 2' },
  { 'min_version':'2024.0', 'fixed_version' : '2024.3.3', 'fixed_display' : '2024 Q3 Patch 3' },
  { 'min_version':'2023.0', 'fixed_version' : '2023.3.6', 'fixed_display' : '2023 Q3 Patch 6' },
  { 'min_version':'2022.0', 'fixed_version' : '2022.3.5', 'fixed_display' : '2022 Q3 Patch 5' },
  { 'min_version':'0', 'max_version' : '2021.999.999', 'fixed_display' : 'Check Vendor Advisory' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
