#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206043);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id(
    "CVE-2024-7964",
    "CVE-2024-7965",
    "CVE-2024-7966",
    "CVE-2024-7967",
    "CVE-2024-7968",
    "CVE-2024-7971",
    "CVE-2024-7972",
    "CVE-2024-7973",
    "CVE-2024-7974",
    "CVE-2024-7975",
    "CVE-2024-7976",
    "CVE-2024-7977",
    "CVE-2024-7978",
    "CVE-2024-7979",
    "CVE-2024-7980",
    "CVE-2024-7981",
    "CVE-2024-8033",
    "CVE-2024-8034",
    "CVE-2024-8035"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/18");
  script_xref(name:"IAVA", value:"2024-A-0519-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/16");

  script_name(english:"Google Chrome < 128.0.6613.84 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 128.0.6613.84. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_08_stable-channel-update-for-desktop_21 advisory.

  - Use after free in Passwords in Google Chrome on Android prior to 128.0.6613.84 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7964)

  - Inappropriate implementation in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7965)

  - Out of bounds memory access in Skia in Google Chrome prior to 128.0.6613.84 allowed a remote attacker who
    had compromised the renderer process to perform out of bounds memory access via a crafted HTML page.
    (Chromium security severity: High) (CVE-2024-7966)

  - Heap buffer overflow in Fonts in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7967)

  - Use after free in Autofill in Google Chrome prior to 128.0.6613.84 allowed a remote attacker who had
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2024-7968)

  - Type confusion in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to exploit heap
    corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-7971)

  - Inappropriate implementation in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to
    potentially perform out of bounds memory access via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2024-7972)

  - Heap buffer overflow in PDFium in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to
    perform an out of bounds memory read via a crafted PDF file. (Chromium security severity: Medium)
    (CVE-2024-7973)

  - Insufficient data validation in V8 API in Google Chrome prior to 128.0.6613.84 allowed a remote attacker
    to potentially exploit heap corruption via a crafted Chrome Extension. (Chromium security severity:
    Medium) (CVE-2024-7974)

  - Inappropriate implementation in Permissions in Google Chrome prior to 128.0.6613.84 allowed a remote
    attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-7975)

  - Inappropriate implementation in FedCM in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to
    perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-7976)

  - Insufficient data validation in Installer in Google Chrome on Windows prior to 128.0.6613.84 allowed a
    local attacker to perform privilege escalation via a malicious file. (Chromium security severity: Medium)
    (CVE-2024-7977)

  - Insufficient policy enforcement in Data Transfer in Google Chrome prior to 128.0.6613.84 allowed a remote
    attacker who convinced a user to engage in specific UI gestures to leak cross-origin data via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2024-7978)

  - Insufficient data validation in Installer in Google Chrome on Windows prior to 128.0.6613.84 allowed a
    local attacker to perform privilege escalation via a crafted symbolic link. (Chromium security severity:
    Medium) (CVE-2024-7979, CVE-2024-7980)

  - Inappropriate implementation in Views in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to
    perform UI spoofing via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-7981)

  - Inappropriate implementation in WebApp Installs in Google Chrome on Windows prior to 128.0.6613.84 allowed
    an attacker who convinced a user to install a malicious application to perform UI spoofing via a crafted
    HTML page. (Chromium security severity: Low) (CVE-2024-8033)

  - Inappropriate implementation in Custom Tabs in Google Chrome on Android prior to 128.0.6613.84 allowed a
    remote attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2024-8034)

  - Inappropriate implementation in Extensions in Google Chrome on Windows prior to 128.0.6613.84 allowed a
    remote attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2024-8035)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ab63593");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/358296941");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/356196918");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/355465305");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/355731798");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/349253666");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/360700873");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/345960102");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/345518608");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/339141099");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/347588491");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/339654392");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/324770940");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40060358");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/356064205");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/356328460");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40067456");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/350256139");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/353858776");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40059470");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 128.0.6613.84 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7974");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-7971");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

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

google_chrome_check_version(installs:installs, fix:'128.0.6613.84', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
