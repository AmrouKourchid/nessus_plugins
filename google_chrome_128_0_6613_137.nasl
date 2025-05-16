#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206911);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id(
    "CVE-2024-8636",
    "CVE-2024-8637",
    "CVE-2024-8638",
    "CVE-2024-8639"
  );
  script_xref(name:"IAVA", value:"2024-A-0568-S");

  script_name(english:"Google Chrome < 128.0.6613.137 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 128.0.6613.137. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_09_stable-channel-update-for-desktop_10 advisory.

  - Heap buffer overflow in Skia in Google Chrome prior to 128.0.6613.137 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-8636)

  - Use after free in Media Router in Google Chrome on Android prior to 128.0.6613.137 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2024-8637)

  - Type Confusion in V8 in Google Chrome prior to 128.0.6613.137 allowed a remote attacker to potentially
    exploit object corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-8638)

  - Use after free in Autofill in Google Chrome on Android prior to 128.0.6613.137 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-8639)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/09/stable-channel-update-for-desktop_10.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e4eceac");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/361461526");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/361784548");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/362539773");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/362658609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 128.0.6613.137 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

google_chrome_check_version(
  installs:installs,
  fix:'128.0.6613.137',
  fixed_display:'128.0.6613.137 / 128.0.6613.138',
  severity:SECURITY_HOLE,
  xss:FALSE,
  xsrf:FALSE);
