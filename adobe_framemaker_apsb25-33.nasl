#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234020);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id(
    "CVE-2025-30295",
    "CVE-2025-30296",
    "CVE-2025-30297",
    "CVE-2025-30298",
    "CVE-2025-30299",
    "CVE-2025-30300",
    "CVE-2025-30301",
    "CVE-2025-30302",
    "CVE-2025-30303",
    "CVE-2025-30304"
  );
  script_xref(name:"IAVB", value:"2025-B-0051");

  script_name(english:"Adobe FrameMaker 2020 < 16.0.8 (2020.0.8) / Adobe FrameMaker 2022 < 17.0.6 (2022.0.6) Multiple Vulnerabilities (APSB25-33)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host is prior to Adobe FrameMaker 2020 16.0.8 / Adobe
FrameMaker 2022 17.0.6. It is, therefore, affected by multiple vulnerabilities as referenced in the apsb25-33 advisory.

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2025-30297,
    CVE-2025-30304)

  - Heap-based Buffer Overflow (CWE-122) potentially leading to Arbitrary code execution (CVE-2025-30295,
    CVE-2025-30299)

  - Integer Underflow (Wrap or Wraparound) (CWE-191) potentially leading to Arbitrary code execution
    (CVE-2025-30296)

  - Stack-based Buffer Overflow (CWE-121) potentially leading to Arbitrary code execution (CVE-2025-30298)

  - NULL Pointer Dereference (CWE-476) potentially leading to Application denial-of-service (CVE-2025-30300,
    CVE-2025-30301)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb25-33.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker FrameMaker 2020 Update 8, FrameMaker 2022 Update 6 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 122, 125, 191, 476, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe FrameMaker', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '16.0.8', 'fixed_display' : '16.0.8 / 2020.0.8 / FrameMaker 2020 Update 8' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.0.6', 'fixed_display' : '17.0.6 / 2022.0.6 / FrameMaker 2022 Update 6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
