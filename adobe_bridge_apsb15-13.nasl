#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209347);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2015-3110", "CVE-2015-3111", "CVE-2015-3112");

  script_name(english:"Adobe Bridge 6.x < 6.1.1 Multiple Vulnerabilities (APSB15-13)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Windows host is prior to 6.1.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the apsb15-13 advisory.

  - Heap-based buffer overflow in Adobe Photoshop CC before 16.0 (aka 2015.0.0) and Adobe Bridge CC before
    6.11 allows attackers to execute arbitrary code via unspecified vectors. (CVE-2015-3111)

  - Adobe Photoshop CC before 16.0 (aka 2015.0.0) and Adobe Bridge CC before 6.11 allow attackers to execute
    arbitrary code or cause a denial of service (memory corruption) via unspecified vectors. (CVE-2015-3112)

  - Integer overflow in Adobe Photoshop CC before 16.0 (aka 2015.0.0) and Adobe Bridge CC before 6.11 allows
    attackers to execute arbitrary code via unspecified vectors. (CVE-2015-3110)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb15-13.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 6.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3112");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-3111");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_bridge_installed.nasl");
  script_require_keys("installed_sw/Adobe Bridge", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Bridge', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '6.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
