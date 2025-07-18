#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159666);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2022-23205",
    "CVE-2022-24098",
    "CVE-2022-24099",
    "CVE-2022-24105",
    "CVE-2022-28270",
    "CVE-2022-28271",
    "CVE-2022-28272",
    "CVE-2022-28273",
    "CVE-2022-28274",
    "CVE-2022-28275",
    "CVE-2022-28276",
    "CVE-2022-28277",
    "CVE-2022-28278",
    "CVE-2022-28279"
  );
  script_xref(name:"IAVA", value:"2022-A-0148-S");

  script_name(english:"Adobe Photoshop 22.x < 22.5.7 / 23.x < 23.3 Multiple Vulnerabilities (APSB22-20)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote Windows host is prior to 22.5.7/23.3. It is, therefore, affected
by multiple vulnerabilities as referenced in the apsb22-20 advisory.

  - Adobe Photoshop versions 22.5.6 (and earlier)and 23.2.2 (and earlier) are affected by a use-after-free
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-28279)

  - Adobe Photoshop versions 22.5.6 (and earlier) and 23.2.2 (and earlier) are affected by an out-of-bounds
    write vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2022-28272, CVE-2022-28273, CVE-2022-28275, CVE-2022-28276, CVE-2022-28278)

  - Adobe Photoshop versions 22.5.6 (and earlier) and 23.2.2 (and earlier) are affected by an out-of-bounds
    write vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious SVG file.
    (CVE-2022-28270)

  - Adobe Photoshop versions 22.5.6 (and earlier)and 23.2.2 (and earlier) are affected by a use-after-free
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious PDF file.
    (CVE-2022-28271)

  - Adobe Photoshop versions 22.5.6 (and earlier) and 23.2.2 (and earlier) are affected by an out-of-bounds
    read vulnerability when parsing a crafted file, which could result in a read past the end of an allocated
    memory structure. An attacker could leverage this vulnerability to execute code in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2022-28274)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb22-20.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 22.5.7/23.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28279");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28278");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 125, 416, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Photoshop', win_local:TRUE);

var constraints = [
  { 'min_version' : '22.0.0', 'fixed_version' : '22.5.7' },
  { 'min_version' : '23.0.0', 'fixed_version' : '23.2.3', 'fixed_display' : '23.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
