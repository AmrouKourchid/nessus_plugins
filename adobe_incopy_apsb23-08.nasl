#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169889);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2023-21594",
    "CVE-2023-21595",
    "CVE-2023-21596",
    "CVE-2023-21597",
    "CVE-2023-21598",
    "CVE-2023-21599"
  );
  script_xref(name:"IAVA", value:"2023-A-0021-S");

  script_name(english:"Adobe InCopy < 17.4.1 / 18.0 < 18.1.0 Multiple Vulnerabilities (APSB23-08)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InCopy instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InCopy installed on the remote host is prior to 17.4.1, 18.1.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB23-08 advisory.

  - Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds write
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2023-21595, CVE-2023-21597)

  - Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by a Heap-based Buffer Overflow
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2023-21594)

  - Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an Improper Input Validation
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2023-21596)

  - Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by a Use After Free
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2023-21598)

  - Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds read
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2023-21599)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/incopy/apsb23-08.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InCopy version 17.4.1, 18.1.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21597");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 122, 125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:incopy");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_incopy_win_installed.nbin", "adobe_incopy_mac_installed.nbin");
  script_require_keys("installed_sw/Adobe InCopy");

  exit(0);
}

include('vcf.inc');

var app = 'Adobe InCopy';
var win_local;
if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;
else
  win_local = FALSE;

var app_info = vcf::get_app_info(app:app, win_local:win_local);

var constraints = [
  { 'fixed_version' : '17.4.1', 'fixed_display' : 'Release: ID17.4.1' },
  { 'min_version' : '18.0', 'fixed_version' : '18.1.0', 'fixed_display' : 'Release: ID18.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
