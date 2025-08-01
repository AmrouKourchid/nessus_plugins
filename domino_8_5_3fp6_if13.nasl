#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92786);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2016-0277",
    "CVE-2016-0278",
    "CVE-2016-0279",
    "CVE-2016-0301",
    "CVE-2016-0304"
  );
  script_bugtraq_id(
    90804,
    91098,
    91099,
    91142,
    91149
  );

  script_name(english:"IBM Domino 8.5.x < 8.5.3 Fix Pack 6 Interim Fix 13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A business collaboration application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM Domino (formerly IBM
Lotus Domino) running on the remote host is 8.5.x prior to 8.5.3 Fix
Pack 6 (FP6) Interim Fix 13 (IF13). It is, therefore, affected by the
following vulnerabilities :

  - Multiple heap-based buffer overflow conditions exist in
    the KeyView PDF filter when parsing a PDF document due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these, by
    convincing a user to open a specially crafted PDF
    document, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2016-0277,
    CVE-2016-0278, CVE-2016-0279, CVE-2016-0301)

  - A security restriction bypass vulnerability exists in
    the remote console due to an error that occurs when an
    unspecified unsupported configuration is used involving
    UNC share path names. An unauthenticated, remote
    attacker can exploit this to bypass authentication and
    possibly execute arbitrary code with SYSTEM privileges.
    (CVE-2016-0304)");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21983292");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21983328");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino version 8.5.3 FP6 IF13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0304");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "IBM Domino";
ver = get_kb_item_or_exit("Domino/Version");
port = get_kb_item("Domino/Version_provided_by_port");
if (!port) port = 0;
version = NULL;
fix = NULL;
fix_ver = NULL;
fix_pack = NULL;
hotfix = NULL;

# Do not have data on special fixes
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Ensure sufficient granularity
if (ver !~ "^(\d+\.){1,}\d+.*$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, ver);

# Only check for 8.5.0.x through 8.5.3.x versions
if (ver =~ "^8\.5\.[0-3]($|[^0-9])")
{
  fix = "8.5.3 FP6 IF13";
  fix_ver = "8.5.3";
  fix_pack = 6;
  hotfix = 2698;
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);

# Breakdown the version into components.
version = eregmatch(string:ver, pattern:"^((?:\d+\.){1,}\d+)(?: FP(\d+))?(?: HF(\d+))?$");
if (isnull(version)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Use 0 as a placeholder if no FP or HF. Version number itself was
# checked for in the granularity check.
if (!version[2]) version[2] = 0;
else version[2] = int(version[2]);
if (!version[3]) version[3] = 0;
else version[3] = int(version[3]);

# Compare current to fix and report as needed.
if (
  ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == -1 ||
  (ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] < fix_pack) ||
  (ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] == fix_pack && version[3] < hotfix)
)
{
  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n'
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);
