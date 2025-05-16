#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232594);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id(
    "CVE-2025-24452",
    "CVE-2025-24453",
    "CVE-2025-27166",
    "CVE-2025-27171",
    "CVE-2025-27175",
    "CVE-2025-27176",
    "CVE-2025-27177",
    "CVE-2025-27178",
    "CVE-2025-27179"
  );
  script_xref(name:"IAVA", value:"2025-A-0152");

  script_name(english:"Adobe InDesign < 19.5.3 / 20.0 < 20.2.0 Multiple Vulnerabilities (APSB25-19)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior to 19.5.3, 20.2.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB25-19 advisory.

  - Out-of-bounds Write (CWE-787) potentially leading to Memory Leak (CVE-2025-24452, CVE-2025-27178)

  - Heap-based Buffer Overflow (CWE-122) potentially leading to Arbitrary code execution (CVE-2025-24453,
    CVE-2025-27171, CVE-2025-27177)

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2025-27166,
    CVE-2025-27175)

  - NULL Pointer Dereference (CWE-476) potentially leading to Application denial-of-service (CVE-2025-27176,
    CVE-2025-27179)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb25-19.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 19.5.3, 20.2.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27178");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 476, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

var constraints = [
  { 'max_version' : '19.5.2', 'fixed_version' : '19.5.3', 'fixed_display' : 'ID19.5.3' },
  { 'min_version' : '20.0', 'fixed_version' : '20.2.0', 'fixed_display' : 'ID20.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
