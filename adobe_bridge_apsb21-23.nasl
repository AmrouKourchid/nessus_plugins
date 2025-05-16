##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148454);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-21091",
    "CVE-2021-21092",
    "CVE-2021-21093",
    "CVE-2021-21094",
    "CVE-2021-21095",
    "CVE-2021-21096"
  );

  script_name(english:"Adobe Bridge 10.x < 10.1.2 / 11.x < 11.0.2 Multiple Vulnerabilities (APSB21-23)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Windows host is prior to 10.1.2 or 11.0.2. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb21-23 advisory.

  - Adobe Bridge versions 10.1.1 (and earlier) and 11.0.1 (and earlier) are affected by an Out-of-bounds write
    vulnerability when parsing a crafted file. An unauthenticated attacker could leverage this vulnerability
    to achieve arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2021-21095)

  - Adobe Bridge versions 10.1.1 (and earlier) and 11.0.1 (and earlier) are affected by an Improper
    Authorization vulnerability in the Genuine Software Service. A low-privileged attacker could leverage this
    vulnerability to achieve application denial-of-service in the context of the current user. Exploitation of
    this issue does not require user interaction. (CVE-2021-21096)

  - Adobe Bridge versions 10.1.1 (and earlier) and 11.0.1 (and earlier) are affected by an Out-of-bounds read
    vulnerability when parsing a crafted file. An unauthenticated attacker could leverage this vulnerability
    to disclose sensitive memory information in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2021-21091)

  - Adobe Bridge versions 10.1.1 (and earlier) and 11.0.1 (and earlier) are affected by a memory corruption
    vulnerability when parsing a specially crafted file. An unauthenticated attacker could leverage this
    vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-21092,
    CVE-2021-21093)

  - Adobe Bridge versions 10.1.1 (and earlier) and 11.0.1 (and earlier) are affected by an Out-of-bounds write
    vulnerability when parsing a specially crafted file. An unauthenticated attacker could leverage this
    vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-21094)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb21-23.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 10.1.2 or 11.0.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21095");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21096");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_bridge_installed.nasl");
  script_require_keys("installed_sw/Adobe Bridge", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Bridge', win_local:TRUE);

var constraints = [
  { 'min_version' : '10.0.0', 'fixed_version' : '10.1.2' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
