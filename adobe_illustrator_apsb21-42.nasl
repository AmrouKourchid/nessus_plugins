#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151660);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-28591",
    "CVE-2021-28592",
    "CVE-2021-28593",
    "CVE-2021-36008",
    "CVE-2021-36009",
    "CVE-2021-36010",
    "CVE-2021-36011"
  );
  script_xref(name:"IAVA", value:"2021-A-0302-S");

  script_name(english:"Adobe Illustrator < 25.3.0 Multiple Vulnerabilities (APSB21-42)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Illustrator instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator installed on the remote Windows host is prior to 25.3.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB21-42 advisory.

  - Adobe Illustrator version 25.2.3 (and earlier) is affected by a potential Command injection vulnerability
    when chained with a development and debugging tool for JavaScript scripts. An unauthenticated attacker
    could leverage this vulnerability to achieve arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-36011)

  - Adobe Illustrator version 25.2.3 (and earlier) is affected by a Use After Free vulnerability when parsing
    a specially crafted file. An unauthenticated attacker could leverage this vulnerability to disclose
    potential sensitive information in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2021-28593)

  - Adobe Illustrator version 25.2.3 (and earlier) is affected by an Use-after-free vulnerability when parsing
    a specially crafted file. An unauthenticated attacker could leverage this vulnerability to read arbitrary
    file system information in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2021-36008)

  - Adobe Illustrator version 25.2.3 (and earlier) is affected by an Out-of-bounds Write vulnerability when
    parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve
    arbitrary code execution in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2021-28591, CVE-2021-28592)

  - Adobe Illustrator version 25.2.3 (and earlier) is affected by an out-of-bounds read vulnerability that
    could lead to disclosure of memory. An attacker could leverage this vulnerability to bypass mitigations
    such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2021-36010)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb21-42.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator version 25.3.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(125, 416, 78, 787, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Illustrator");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Illustrator', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '25.3.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
