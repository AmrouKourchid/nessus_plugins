#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205601);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2024-39383",
    "CVE-2024-39420",
    "CVE-2024-39422",
    "CVE-2024-39423",
    "CVE-2024-39424",
    "CVE-2024-39425",
    "CVE-2024-39426",
    "CVE-2024-41830",
    "CVE-2024-41831",
    "CVE-2024-41832",
    "CVE-2024-41833",
    "CVE-2024-41834",
    "CVE-2024-41835",
    "CVE-2024-45107"
  );
  script_xref(name:"IAVA", value:"2024-A-0474-S");

  script_name(english:"Adobe Reader < 20.005.30655 / 24.002.21005 Multiple Vulnerabilities (APSB24-57)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior to 20.005.30655 or 24.002.21005. It
is, therefore, affected by multiple vulnerabilities.

  - Acrobat Reader versions 20.005.30636, 24.002.20965, 24.002.20964, 24.001.30123 and earlier are affected by
    a Use After Free vulnerability that could result in arbitrary code execution in the context of the current
    user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-39383, CVE-2024-39422, CVE-2024-39424, CVE-2024-41830, CVE-2024-41831)

  - Acrobat Reader versions 20.005.30636, 24.002.20965, 24.002.20964, 24.001.30123 and earlier are affected by
    an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2024-39423)

  - Acrobat Reader versions 20.005.30636, 24.002.20965, 24.002.20964, 24.001.30123 and earlier are affected by
    a Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability that could lead to privilege escalation.
    Exploitation of this issue require local low-privilege access to the affected system and attack complexity
    is high. (CVE-2024-39425)

  - Acrobat Reader versions 20.005.30636, 24.002.20965, 24.002.20964, 24.001.30123 and earlier are affected by
    an out-of-bounds read vulnerability when parsing a crafted file, which could result in a read past the end
    of an allocated memory structure. An attacker could leverage this vulnerability to execute code in the
    context of the current user. Exploitation of this issue requires user interaction in that a victim must
    open a malicious file. (CVE-2024-39426)

  - Acrobat Reader versions 20.005.30636, 24.002.21005, 24.001.30159, 20.005.30655, 24.002.20965,
    24.002.20964, 24.001.30123, 24.003.20054 and earlier are affected by a Time-of-check Time-of-use (TOCTOU)
    Race Condition vulnerability that could lead to arbitrary code execution. This vulnerability arises when
    the timing of actions changes the state of a resource between the checking of a condition and the use of
    the resource, allowing an attacker to manipulate the resource in a harmful way. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2024-39420)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb24-57.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 20.005.30655 / 24.002.21005 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41831");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(125, 347, 367, 416, 787, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe Reader', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
var constraints = [
  { 'min_version' : '20.1', 'max_version' : '20.005.30636', 'fixed_version' : '20.005.30655', 'track' : 'DC Classic' },
  { 'min_version' : '15.7', 'max_version' : '24.002.20991', 'fixed_version' : '24.002.21005', 'track' : 'DC Continuous' }
];
vcf::adobe_acrobat::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    max_segs:3,
    severity:SECURITY_HOLE
);
