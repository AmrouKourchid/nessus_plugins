#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205442);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2024-34117");
  script_xref(name:"IAVA", value:"2024-A-0480-S");

  script_name(english:"Adobe Photoshop 24.x < 24.7.4 / 25.x < 25.11 Vulnerability (APSB24-49)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote Windows host is prior to 24.7.4/25.11. It is, therefore, affected
by a vulnerability as referenced in the apsb24-49 advisory.

  - Photoshop Desktop versions 24.7.3, 25.9.1 and earlier are affected by a Use After Free vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2024-34117)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb24-49.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 24.7.4/25.11 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34117");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Photoshop', win_local:TRUE);

var constraints = [
  { 'min_version' : '24.0.0', 'fixed_version' : '24.7.4' },
  { 'min_version' : '25.0.0', 'fixed_version' : '25.9.2', 'fixed_display' : '25.11' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
