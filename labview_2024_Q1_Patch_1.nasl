#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192110);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2024-23608",
    "CVE-2024-23609",
    "CVE-2024-23610",
    "CVE-2024-23611",
    "CVE-2024-23612"
  );
  script_xref(name:"IAVA", value:"2024-A-0168-S");

  script_name(english:"National Instruments LabVIEW < 2024 Q1 Patch 1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of National Instruments (NI) LabVIEW installed on the remote Windows host is version 2015 prior to 2024 
Q1 Patch 1. It is therefore affected by multiple vulnerabilities:

  - An out of bounds write due to a missing bounds check in LabVIEW may result in remote code execution. Successful 
    exploitation requires an attacker to provide a user with a specially crafted VI. (CVE-2024-23608)

  - An improper error handling vulnerability in LabVIEW may result in remote code execution. Successful exploitation 
    requires an attacker to provide a user with a specially crafted VI. (CVE-2024-23609)
    
  - An out of bounds write due to a missing bounds check in LabVIEW may result in remote code execution. Successful 
    exploitation requires an attacker to provide a user with a specially crafted VI. (CVE-2024-23610)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6b68791");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NI LabVIEW version 2024 Q1 Patch 1 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23611");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ni:labview");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("labview_installed.nbin");
  script_require_keys("installed_sw/National Instruments LabVIEW", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'National Instruments LabVIEW');

var constraints = [
  { 'fixed_version' : '2024.1.1', 'fixed_display' : '2024 Q1 Patch 1' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
