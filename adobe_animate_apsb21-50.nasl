#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150419);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2021-28617",
    "CVE-2021-28618",
    "CVE-2021-28619",
    "CVE-2021-28620",
    "CVE-2021-28621",
    "CVE-2021-28622",
    "CVE-2021-28629",
    "CVE-2021-28630"
  );
  script_xref(name:"IAVA", value:"2021-A-0268-S");

  script_name(english:"Adobe Animate 21.x < 21.0.7 Multiple Vulnerabilities (APSB21-50)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Animate installed on remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Animate installed on the remote Windows host is prior to 21.0.7. It is, therefore, affected by
multiple vulnerabilities as referenced in the apsb21-50 advisory.

  - Adobe Animate version 21.0.6 (and earlier) is affected by an Out-of-bounds Read vulnerability. An
    unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-28621)

  - Adobe Animate version 21.0.6 (and earlier) is affected by an Out-of-bounds Read vulnerability when parsing
    a specially crafted file. An unauthenticated attacker could leverage this vulnerability to disclose
    potential sensitive information in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2021-28630)

  - Adobe Animate version 21.0.6 (and earlier) is affected by an Out-of-bounds Read vulnerability when parsing
    a specially crafted file. An unauthenticated attacker could leverage this vulnerability to disclose
    sensitive memory information in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2021-28617, CVE-2021-28618, CVE-2021-28619)

  - Adobe Animate version 21.0.6 (and earlier) is affected by a Heap-based Buffer Overflow vulnerability. An
    unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-28620, CVE-2021-28629)

  - Adobe Animate version 21.0.6 (and earlier) is affected by an Out-of-bounds Write vulnerability. An
    unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2021-28622)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/animate/apsb21-50.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Animate version 21.0.7 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28630");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 125, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/09");

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
  { 'min_version' : '21.0.0', 'fixed_version' : '21.0.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
