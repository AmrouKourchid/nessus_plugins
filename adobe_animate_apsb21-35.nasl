#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149451);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2021-28572",
    "CVE-2021-28573",
    "CVE-2021-28574",
    "CVE-2021-28575",
    "CVE-2021-28576",
    "CVE-2021-28577",
    "CVE-2021-28578"
  );
  script_xref(name:"IAVA", value:"2021-A-0230-S");

  script_name(english:"Adobe Animate 20.x < 20.5.2 / 21.x < 21.0.6 Multiple Vulnerabilities (APSB21-35)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Animate installed on remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Animate installed on the remote Windows host is prior to 20.5.2 or 21.0.6. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb21-35 advisory.

  - Adobe Animate version 21.0.5 (and earlier) is affected by an Out-of-bounds Read vulnerability when parsing
    a specially crafted file. An unauthenticated attacker could leverage this vulnerability to disclose
    sensitive information in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2021-28573, CVE-2021-28574, CVE-2021-28575,
    CVE-2021-28576)

  - Out-of-bounds read potentially leading to Information Disclosure (CVE-2021-28572)

  - Use After Free potentially leading to Arbitrary code execution (CVE-2021-28578)

  - Out-of-bounds write potentially leading to Arbitrary code execution (CVE-2021-28577)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/animate/apsb21-35.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Animate version 20.5.2 or 21.0.6 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28576");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28573");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:animate");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_animate_installed.nbin");
  script_require_keys("installed_sw/Adobe Animate", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Animate', win_local:TRUE);

var constraints = [
  { 'min_version' : '20.0.0', 'fixed_version' : '20.5.2' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
