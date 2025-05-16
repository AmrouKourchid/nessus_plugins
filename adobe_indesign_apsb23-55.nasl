#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185567);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2023-44341",
    "CVE-2023-44342",
    "CVE-2023-44343",
    "CVE-2023-44344",
    "CVE-2023-44345",
    "CVE-2023-44346",
    "CVE-2023-44347"
  );
  script_xref(name:"IAVA", value:"2023-A-0627-S");

  script_name(english:"Adobe InDesign < 18.5.1 / 18.0 < 19.0.0 Multiple Vulnerabilities (APSB23-55)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior to 18.5.1, 19.0.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB23-55 advisory.

  - Adobe InDesign versions ID18.5 (and earlier) and ID17.4.2 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2023-44342, CVE-2023-44343, CVE-2023-44344, CVE-2023-44346)

  - Adobe InDesign versions ID18.5 (and earlier) and ID17.4.2 (and earlier) are affected by a NULL Pointer
    Dereference vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve an
    application denial-of-service in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2023-44341, CVE-2023-44347)

  - Adobe InDesign versions ID18.5 (and earlier) and ID17.4.2 (and earlier) are affected by a Improper Input
    Validation vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve an
    application denial-of-service in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2023-44345)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb23-55.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 18.5.1, 19.0.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44346");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 20, 476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

var constraints = [
  { 'max_version' : '17.4.2', 'fixed_version' : '18.5.1', 'fixed_display' : 'ID18.5.1' },
  { 'min_version' : '18.0', 'max_version' : '18.5', 'fixed_version' : '19.0.0', 'fixed_display' : 'ID19.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
