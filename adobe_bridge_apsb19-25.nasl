#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124089);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id(
    "CVE-2019-7130",
    "CVE-2019-7132",
    "CVE-2019-7133",
    "CVE-2019-7134",
    "CVE-2019-7135",
    "CVE-2019-7136",
    "CVE-2019-7137",
    "CVE-2019-7138"
  );
  script_bugtraq_id(
    107810,
    107813,
    107820,
    107823
  );

  script_name(english:"Adobe Bridge 9.0.2 < 9.0.3 Multiple Vulnerabilities (APSB19-25)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Windows host is prior to 9.0.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the apsb19-25 advisory.

  - Adobe Bridge CC versions 9.0.2 have a heap overflow vulnerability. Successful exploitation could lead to
    remote code execution. (CVE-2019-7130)

  - Adobe Bridge CC versions 9.0.2 have an out-of-bounds write vulnerability. Successful exploitation could
    lead to remote code execution. (CVE-2019-7132)

  - Adobe Bridge CC versions 9.0.2 have an out-of-bounds read vulnerability. Successful exploitation could
    lead to information disclosure. (CVE-2019-7133, CVE-2019-7134, CVE-2019-7135, CVE-2019-7138)

  - Adobe Bridge CC versions 9.0.2 have an use after free vulnerability. Successful exploitation could lead to
    information disclosure. (CVE-2019-7136)

  - Adobe Bridge CC versions 9.0.2 have a memory corruption vulnerability. Successful exploitation could lead
    to information disclosure. (CVE-2019-7137)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb19-25.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 9.0.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7130");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_bridge_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Bridge");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Bridge', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.0.3', 'equal' : '9.0.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
