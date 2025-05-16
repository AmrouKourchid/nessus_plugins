#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209038);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/03");

  script_cve_id(
    "CVE-2024-9954",
    "CVE-2024-9955",
    "CVE-2024-9956",
    "CVE-2024-9957",
    "CVE-2024-9958",
    "CVE-2024-9959",
    "CVE-2024-9960",
    "CVE-2024-9961",
    "CVE-2024-9962",
    "CVE-2024-9963",
    "CVE-2024-9964",
    "CVE-2024-9965",
    "CVE-2024-9966"
  );
  script_xref(name:"IAVA", value:"2024-A-0667-S");

  script_name(english:"Google Chrome < 130.0.6723.58 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 130.0.6723.58. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_10_stable-channel-update-for-desktop_15 advisory.

  - Use after free in AI. (CVE-2024-9954)

  - Use after free in Web Authentication. (CVE-2024-9955)

  - Inappropriate implementation in Web Authentication. (CVE-2024-9956)

  - Use after free in UI. (CVE-2024-9957)

  - Inappropriate implementation in PictureInPicture. (CVE-2024-9958)

  - Use after free in DevTools. (CVE-2024-9959)

  - Use after free in Dawn. (CVE-2024-9960)

  - Use after free in Parcel Tracking. (CVE-2024-9961)

  - Inappropriate implementation in Permissions. (CVE-2024-9962)

  - Insufficient data validation in Downloads. (CVE-2024-9963)

  - Inappropriate implementation in Payments. (CVE-2024-9964)

  - Insufficient data validation in DevTools. (CVE-2024-9965)

  - Inappropriate implementation in Navigations. (CVE-2024-9966)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/10/stable-channel-update-for-desktop_15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5572891");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/367755363");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/370133761");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/370482421");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/358151317");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40076120");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/368672129");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/354748063");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/357776197");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/364508693");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/328278718");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/361711121");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/352651673");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/364773822");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 130.0.6723.58 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9965");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

google_chrome_check_version(installs:installs, fix:'130.0.6723.58', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
