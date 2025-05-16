#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197003);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/23");

  script_cve_id("CVE-2024-4558", "CVE-2024-4559");
  script_xref(name:"IAVA", value:"2024-A-0272-S");

  script_name(english:"Google Chrome < 124.0.6367.155 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 124.0.6367.155. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_05_stable-channel-update-for-desktop_7 advisory.

  - Use after free in ANGLE in Google Chrome prior to 124.0.6367.155 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-4558)

  - Heap buffer overflow in WebAudio in Google Chrome prior to 124.0.6367.155 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-4559)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/05/stable-channel-update-for-desktop_7.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9364f86a");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/337766133");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/331369797");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 124.0.6367.155 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4558");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

google_chrome_check_version(installs:installs, fix:'124.0.6367.155', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
