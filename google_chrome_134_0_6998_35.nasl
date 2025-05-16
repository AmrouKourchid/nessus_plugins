#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226073);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id(
    "CVE-2025-1914",
    "CVE-2025-1915",
    "CVE-2025-1916",
    "CVE-2025-1917",
    "CVE-2025-1918",
    "CVE-2025-1919",
    "CVE-2025-1921",
    "CVE-2025-1922",
    "CVE-2025-1923"
  );
  script_xref(name:"IAVA", value:"2025-A-0143-S");

  script_name(english:"Google Chrome < 134.0.6998.35 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 134.0.6998.35. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2025_03_stable-channel-update-for-desktop advisory.

  - Use after free in Profiles. (CVE-2025-1916)

  - Out of bounds read in V8. (CVE-2025-1914)

  - Improper Limitation of a Pathname to a Restricted Directory in DevTools. (CVE-2025-1915)

  - Inappropriate Implementation in Browser UI. (CVE-2025-1917)

  - Out of bounds read in PDFium. (CVE-2025-1918)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2025/03/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e22c0822");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/397731718");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/391114799");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/376493203");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/329476341");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/388557904");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/392375312");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/387583503");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/384033062");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/382540635");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 134.0.6998.35 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1916");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');
include('smb_hotfixes.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

if (hotfix_check_sp_range(win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

google_chrome_check_version(installs:installs, fix:'134.0.6998.35', fixed_display:'134.0.6998.35 / 134.0.6998.36', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
