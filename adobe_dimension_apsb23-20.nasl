#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172600);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2023-25879",
    "CVE-2023-25880",
    "CVE-2023-25881",
    "CVE-2023-25882",
    "CVE-2023-25883",
    "CVE-2023-25884",
    "CVE-2023-25885",
    "CVE-2023-25886",
    "CVE-2023-25887",
    "CVE-2023-25888",
    "CVE-2023-25889",
    "CVE-2023-25890",
    "CVE-2023-25891",
    "CVE-2023-25892",
    "CVE-2023-25893",
    "CVE-2023-25894",
    "CVE-2023-25895",
    "CVE-2023-25896",
    "CVE-2023-25897",
    "CVE-2023-25898",
    "CVE-2023-25899",
    "CVE-2023-25900",
    "CVE-2023-25901",
    "CVE-2023-25902",
    "CVE-2023-25903",
    "CVE-2023-25904",
    "CVE-2023-25905",
    "CVE-2023-25906",
    "CVE-2023-25907",
    "CVE-2023-26327",
    "CVE-2023-26328",
    "CVE-2023-26329",
    "CVE-2023-26330",
    "CVE-2023-26331",
    "CVE-2023-26332",
    "CVE-2023-26333",
    "CVE-2023-26334",
    "CVE-2023-26335",
    "CVE-2023-26336",
    "CVE-2023-26337",
    "CVE-2023-26338",
    "CVE-2023-26339",
    "CVE-2023-26340",
    "CVE-2023-26341",
    "CVE-2023-26342",
    "CVE-2023-26343",
    "CVE-2023-26344",
    "CVE-2023-26345",
    "CVE-2023-26346",
    "CVE-2023-26348",
    "CVE-2023-26349",
    "CVE-2023-26350",
    "CVE-2023-26351",
    "CVE-2023-26352",
    "CVE-2023-26353",
    "CVE-2023-26354",
    "CVE-2023-26355",
    "CVE-2023-26356"
  );
  script_xref(name:"IAVA", value:"2023-A-0146-S");

  script_name(english:"Adobe Dimension < 3.4.8 Multiple Vulnerabilities (APSB23-20)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Dimension instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dimension installed on the remote Windows host is prior to 3.4.8. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB23-20 advisory.

  - Adobe Dimension versions 3.4.7 (and earlier) is affected by a Stack-based Buffer Overflow vulnerability
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2023-26337)

  - Adobe Dimension versions 3.4.7 (and earlier) is affected by an Improper Input Validation vulnerability
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2023-25879,
    CVE-2023-25881, CVE-2023-25901)

  - Adobe Dimension versions 3.4.7 (and earlier) is affected by an out-of-bounds write vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2023-25880, CVE-2023-25905,
    CVE-2023-26328, CVE-2023-26330)

  - Adobe Dimension versions 3.4.7 (and earlier) is affected by a Heap-based Buffer Overflow vulnerability
    that could result in arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2023-25882,
    CVE-2023-25883, CVE-2023-25885, CVE-2023-25890, CVE-2023-25895, CVE-2023-25897, CVE-2023-25898)

  - Adobe Dimension versions 3.4.7 (and earlier) is affected by an out-of-bounds read vulnerability when
    parsing a crafted file, which could result in a read past the end of an allocated memory structure. An
    attacker could leverage this vulnerability to execute code in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2023-25884, CVE-2023-25886, CVE-2023-25887, CVE-2023-25888, CVE-2023-25889, CVE-2023-25891,
    CVE-2023-25892, CVE-2023-25900, CVE-2023-25902, CVE-2023-25904, CVE-2023-25906, CVE-2023-25907,
    CVE-2023-26333, CVE-2023-26335)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dimension/apsb23-20.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dimension version 3.4.8 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 121, 122, 125, 190, 416, 787, 824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dimension");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dimension_installed.nbin");
  script_require_keys("installed_sw/Adobe Dimension", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Dimension', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '3.4.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
