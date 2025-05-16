#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212761);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2024-10494", "CVE-2024-10495", "CVE-2024-10496");
  script_xref(name:"IAVA", value:"2024-A-0802-S");

  script_name(english:"National Instruments LabVIEW < 2024 Q3 Patch 2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of National Instruments LabVIEW installed on the remote host is prior to 2022 Q3 Patch 4, 2023 Q3 Patch 5,
or 2024 Q3 Patch 2. It is, therefore, affected by multiple vulnerabilities as referenced in the 2024_Q3_P2 advisory.

  - An out of bounds read due to improper input validation in HeapObjMapImpl.cpp in NI LabVIEW may disclose
    information or result in arbitrary code execution. Successful exploitation requires an attacker to provide
    a user with a specially crafted VI. This vulnerability affects LabVIEW 2024 Q3 and prior versions.
    (CVE-2024-10494)

  - An out of bounds read due to improper input validation when loading the font table in fontmgr.cpp in NI
    LabVIEW may disclose information or result in arbitrary code execution. Successful exploitation requires
    an attacker to provide a user with a specially crafted VI. This vulnerability affects LabVIEW 2024 Q3 and
    prior versions. (CVE-2024-10495)

  - An out of bounds read due to improper input validation in BuildFontMap in fontmgr.cpp in NI LabVIEW may
    disclose information or result in arbitrary code execution. Successful exploitation requires an attacker
    to provide a user with a specially crafted VI. This vulnerability affects LabVIEW 2024 Q3 and prior
    versions. (CVE-2024-10496)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/out-of-bounds-read-vulnerabilities-in-ni-labview-.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?251a3bdb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to National Instruments LabVIEW version 2022 Q3 Patch 4 / 2023 Q3 Patch 5 / 2024 Q3 Patch 2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10496");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ni:labview");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("labview_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/National Instruments LabVIEW");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'National Instruments LabVIEW', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '2022.3.4', 'fixed_display' : '2022 Q3 Patch 4' },
  { 'min_version' : '2023.0', 'fixed_version' : '2023.3.5', 'fixed_display' : '2023 Q3 Patch 5' },
  { 'min_version' : '2024.0', 'fixed_version' : '2024.3.2', 'fixed_display' : '2024 Q3 Patch 2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
