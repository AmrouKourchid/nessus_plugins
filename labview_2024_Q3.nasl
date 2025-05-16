#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204716);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/13");

  script_cve_id("CVE-2024-4079", "CVE-2024-4080", "CVE-2024-4081");
  script_xref(name:"IAVA", value:"2024-A-0444-S");

  script_name(english:"National Instruments LabVIEW < 2024 Q3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of National Instruments (NI) LabVIEW installed on the remote Windows host is affected by multiple
vulnerabilities:

  - An out of bounds read due to a missing bounds check in LabVIEW may disclose information or result in arbitrary code
    execution. Successful exploitation requires an attacker to provide a user with a specially crafted VI. This
    vulnerability affects LabVIEW 2024 Q1 and prior versions. (CVE-2024-4079)

  - A memory corruption issue due to an improper length check in LabVIEW tdcore.dll may disclose information or result
    in arbitrary code execution. Successful exploitation requires an attacker to provide a user with a specially
    crafted VI. This vulnerability affects LabVIEW 2024 Q1 and prior versions. (CVE-2024-4080)

  - A memory corruption issue due to an improper length check in NI LabVIEW may disclose information or result in
    arbitrary code execution. Successful exploitation requires an attacker to provide a user with a specially crafted VI.
    This vulnerability affects NI LabVIEW 2024 Q1 and prior versions. (CVE-2024-4081)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/out-of-bounds-read-due-to-missing-bounds-check-in-labview.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c18789b3");
  # https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/memory-corruption-issues-due-to-improper-length-checks-in-labview.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30427908");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the NI LabVIEW version referenced in the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4081");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ni:labview");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("labview_installed.nbin");
  script_require_keys("installed_sw/National Instruments LabVIEW", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'National Instruments LabVIEW');

var constraints = [
  { 'min_version':'2024.0', 'fixed_version' : '2024.3.1', 'fixed_display' : '2024 Q3 Patch 1' },
  { 'min_version':'2023.0', 'fixed_version' : '2023.3.3', 'fixed_display' : '2023 Q3 Patch 3' },
  { 'min_version':'2022.0', 'fixed_version' : '2022.3.1', 'fixed_display' : '2022 Q3 Patch 1' },
  { 'min_version':'2021.0', 'fixed_version' : '2021.1.2', 'fixed_display' : '2021 SP1 f2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
