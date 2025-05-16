#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192151);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/12");

  script_cve_id("CVE-2024-1403");
  script_xref(name:"IAVA", value:"2024-A-0146");

  script_name(english:"Progress OpenEdge 11.7.x < 11.7.19 / 12.2.x < 12.2.13 / 12.8.x < 12.8.1 (000253075)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Progress OpenEdge installed on the remote host is prior to 11.7.19, 12.2.13, or 12.8.1. It is, therefore,
affected by a vulnerability as referenced in the 000253075 advisory.

  - In OpenEdge Authentication Gateway and AdminServer prior to 11.7.19, 12.2.14, 12.8.1 on all platforms
    supported by the OpenEdge product, an authentication bypass vulnerability has been identified. The
    vulnerability is a bypass to authentication based on a failure to properly handle username and password.
    Certain unexpected content passed into the credentials can lead to unauthorized access without proper
    authentication. (CVE-2024-1403)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/Important-Critical-Alert-for-OpenEdge-Authentication-Gateway-and-AdminServer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?405662ca");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress OpenEdge version 11.7.19 / 12.2.13 / 12.8.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1403");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:openedge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("progress_openedge_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Progress OpenEdge");

  exit(0);
}

include('vcf.inc');
include('lists.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Progress OpenEdge', win_local:TRUE);

var vulnerable_products = [
  # Products that require AdminServer to be installed
  # https://docs.progress.com/bundle/openedge-install-117/page/OpenEdge-products-supported-by-the-AdminServer_2.html
  'OE Personal RDBMS',
  'OE Workgroup RDBMS',
  'OE Enterprise RDBMS',
  'OE Adv. Ent. RDBMS',
  'OE DataServer MS SQL S',
  'OE DataServer MS SQL Svr',
  'OE DataServer for Oracle',
  'OE Application Svr Bas',
  'OE Application Svr Ent',
  'OE Studio',
  'Progress Dev Studio OE',
  'AppServer IntAdap',
  'NameServer',
  'OE Development Server',
  'NameServer Load Balance',
  'WebSpeed Workshop',
  'OpenEdge Replication',
  'OpenEdge Repl Plus',
  # Authentication Gateway
  'OE Auth Gateway'
];

var installed_vulnerable = collib::intersection(keys(app_info), vulnerable_products);

if (empty_or_null(installed_vulnerable))
  vcf::audit(app_info);

# A mitigation is updating the auth.dll file without updating the rest of the installation
# Typically the version should be the same for both, but occasionally this doesn't happen
# so require paranoia if there is a mismatch

var require_paranoia = FALSE;
if (app_info.version != app_info['bin\\auth.dll version'])
  require_paranoia = TRUE;


var constraints = [
  { 'min_version' : '11.7', 'fixed_version' : '11.7.19' },
  { 'min_version' : '12.2', 'fixed_version' : '12.2.13' },
  { 'min_version' : '12.8.0', 'fixed_version' : '12.8.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    require_paranoia:require_paranoia
);
