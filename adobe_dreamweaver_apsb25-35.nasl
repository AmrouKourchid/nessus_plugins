#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235866);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id("CVE-2025-30310");

  script_name(english:"Adobe Dreamweaver 21.0 < 21.5 Arbitrary code execution (APSB25-35)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Dreamweaver instance installed on the remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dreamweaver installed on the remote Windows host is prior to 21.5. It is, therefore, affected by a
vulnerability as referenced in the APSB25-35 advisory.

  - Dreamweaver Desktop versions 21.4 and earlier are affected by an Access of Resource Using Incompatible
    Type ('Type Confusion') vulnerability that could result in arbitrary code execution in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2025-30310)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb25-35.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dreamweaver version 21.5 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30310");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(843);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dreamweaver");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dreamweaver_installed.nasl");
  script_require_keys("installed_sw/Adobe Dreamweaver", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Dreamweaver');

var constraints = [
  { 'min_version' : '21.0', 'max_version' : '21.4', 'fixed_version' : '21.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
