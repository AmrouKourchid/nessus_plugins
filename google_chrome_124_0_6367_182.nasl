#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202490);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2024-6772",
    "CVE-2024-6773",
    "CVE-2024-6774",
    "CVE-2024-6775",
    "CVE-2024-6776",
    "CVE-2024-6777",
    "CVE-2024-6778",
    "CVE-2024-6779"
  );
  script_xref(name:"IAVA", value:"2024-A-0417-S");

  script_name(english:"Google Chrome < 124.0.6367.182 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 124.0.6367.182. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_07_stable-channel-update-for-desktop advisory.

  - Inappropriate implementation in V8 in Google Chrome prior to 126.0.6478.182 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-6772)

  - Inappropriate implementation in V8 in Google Chrome prior to 126.0.6478.182 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-6773)

  - Use after free in Screen Capture in Google Chrome prior to 126.0.6478.182 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: High) (CVE-2024-6774)

  - Use after free in Media Stream in Google Chrome prior to 126.0.6478.182 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: High) (CVE-2024-6775)

  - Use after free in Audio in Google Chrome prior to 126.0.6478.182 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-6776)

  - Use after free in Navigation in Google Chrome prior to 126.0.6478.182 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome
    Extension. (Chromium security severity: High) (CVE-2024-6777)

  - Race in DevTools in Google Chrome prior to 126.0.6478.182 allowed an attacker who convinced a user to
    install a malicious extension to inject scripts or HTML into a privileged page via a crafted Chrome
    Extension. (Chromium security severity: High) (CVE-2024-6778)

  - Out of bounds memory access in V8 in Google Chrome prior to 126.0.6478.182 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-6779)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/07/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51ea8a67");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/346597059");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/347724915");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/346898524");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/347373236");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/346692546");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/345640549");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/341136300");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/351327767");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 124.0.6367.182 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6779");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/16");

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

google_chrome_check_version(installs:installs, fix:'124.0.6367.182', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
