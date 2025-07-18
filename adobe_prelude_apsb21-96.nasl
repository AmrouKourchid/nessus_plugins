#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154727);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id(
    "CVE-2021-40770",
    "CVE-2021-40771",
    "CVE-2021-40772",
    "CVE-2021-40773",
    "CVE-2021-40774",
    "CVE-2021-40775",
    "CVE-2021-42733",
    "CVE-2021-42737",
    "CVE-2021-42738",
    "CVE-2021-43011",
    "CVE-2021-43012"
  );
  script_xref(name:"IAVA", value:"2021-A-0520-S");

  script_name(english:"Adobe Prelude < 22.0 Multiple Vulnerabilities (APSB21-96)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Prelude instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Prelude installed on the remote Windows host is prior to 22.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB21-96 advisory.

  - Adobe Prelude version 10.1 (and earlier) are affected by a memory corruption vulnerability. An
    unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious M4A file. (CVE-2021-43011, CVE-2021-43012)

  - Adobe Prelude version 10.1 (and earlier) is affected by a memory corruption vulnerability due to insecure
    handling of a malicious M4A file, potentially resulting in arbitrary code execution in the context of the
    current user. User interaction is required in that the victim must open a specially crafted file to
    exploit this vulnerability. (CVE-2021-40770, CVE-2021-40772)

  - Adobe Prelude version 10.1 (and earlier) is affected by a memory corruption vulnerability due to insecure
    handling of a malicious WAV file, potentially resulting in arbitrary code execution in the context of the
    current user. User interaction is required in that the victim must open a specially crafted file to
    exploit this vulnerability. (CVE-2021-40771, CVE-2021-42737)

  - Adobe Prelude version 10.1 (and earlier) is affected by a null pointer dereference vulnerability when
    parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve
    an application denial-of-service in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2021-40773, CVE-2021-40774)

  - Adobe Prelude version 10.1 (and earlier) is affected by a memory corruption vulnerability due to insecure
    handling of a malicious SVG file, potentially resulting in arbitrary code execution in the context of the
    current user. User interaction is required in that the victim must open a specially crafted file to
    exploit this vulnerability. (CVE-2021-40775)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/prelude/apsb21-96.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Prelude version 22.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43012");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-40770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 476, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:prelude");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_prelude_installed.nasl");
  script_require_keys("installed_sw/Adobe Prelude", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Prelude', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '22.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
