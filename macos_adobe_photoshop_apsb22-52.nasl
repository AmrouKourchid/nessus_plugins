#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164987);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2022-35713",
    "CVE-2022-38426",
    "CVE-2022-38427",
    "CVE-2022-38428",
    "CVE-2022-38429",
    "CVE-2022-38430",
    "CVE-2022-38431",
    "CVE-2022-38432",
    "CVE-2022-38433",
    "CVE-2022-38434"
  );
  script_xref(name:"IAVA", value:"2022-A-0365-S");

  script_name(english:"Adobe Photoshop 22.x < 22.5.9 / 23.x < 23.5 Multiple Vulnerabilities (macOS APSB22-52)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote macOS or Mac OS X host is prior to 22.5.9/23.5. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb22-52 advisory.

  - Adobe Photoshop versions 22.5.8 (and earlier) and 23.4.2 (and earlier) are affected by a Use After Free
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-38434)

  - Adobe Photoshop versions 22.5.8 (and earlier) and 23.4.2 (and earlier) are affected by an out-of-bounds
    write vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-35713)

  - Adobe Photoshop versions 22.5.8 (and earlier) and 23.4.2 (and earlier) are affected by an Access of
    Uninitialized Pointer vulnerability that could result in arbitrary code execution in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2022-38426, CVE-2022-38427)

  - Adobe Photoshop versions 22.5.8 (and earlier) and 23.4.2 (and earlier) are affected by a Use After Free
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious file. (CVE-2022-38428)

  - Adobe Photoshop versions 22.5.8 (and earlier) and 23.4.2 (and earlier) are affected by an out-of-bounds
    read vulnerability when parsing a crafted file, which could result in a read past the end of an allocated
    memory structure. An attacker could leverage this vulnerability to execute code in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2022-38429, CVE-2022-38430, CVE-2022-38431)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb22-52.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 22.5.9/23.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38434");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 416, 787, 824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_photoshop_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Photoshop");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Photoshop');

var constraints = [
  { 'min_version' : '22.0.0', 'fixed_version' : '22.5.9' },
  { 'min_version' : '23.0.0', 'fixed_version' : '23.4.3', 'fixed_display' : '23.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
