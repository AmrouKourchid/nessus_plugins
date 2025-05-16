#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156228);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-43027",
    "CVE-2021-43755",
    "CVE-2021-44188",
    "CVE-2021-44189",
    "CVE-2021-44190",
    "CVE-2021-44191",
    "CVE-2021-44192",
    "CVE-2021-44193",
    "CVE-2021-44194",
    "CVE-2021-44195"
  );
  script_xref(name:"IAVA", value:"2021-A-0590-S");

  script_name(english:"Adobe After Effects < 18.4.3 / 22.0.0 < 22.1.1 Multiple Vulnerabilities (APSB21-115)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe After Effects instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 18.4.3, 22.1.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB21-115 advisory.

  - Adobe After Effects versions 22.0 (and earlier) and 18.4.2 (and earlier) are affected by an out-of-bounds
    read vulnerability which could result in a read past the end of an allocated memory structure. An attacker
    could leverage this vulnerability to execute code in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-43027,
    CVE-2021-44188)

  - Adobe After Effects versions 22.0 (and earlier) and 18.4.2 (and earlier) are affected by an Out-of-bounds
    Write vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code
    execution in the context of the current user. User interaction is required to exploit this vulnerability.
    (CVE-2021-43755)

  - Adobe After Effects versions 22.0 (and earlier) and 18.4.2 (and earlier) are affected by an Use-After-Free
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2021-44189)

  - Adobe After Effects versions 22.0 (and earlier) and 18.4.2 (and earlier) are affected by an out-of-bounds
    read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2021-44190, CVE-2021-44191, CVE-2021-44192, CVE-2021-44193,
    CVE-2021-44194, CVE-2021-44195)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/after_effects/apsb21-115.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09720458");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 18.4.3, 22.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43755");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-44188");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 416, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '18.4.3' },
  { 'min_version' : '22.0.0', 'fixed_version' : '22.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
