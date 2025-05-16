#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193368);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2024-3832",
    "CVE-2024-3833",
    "CVE-2024-3834",
    "CVE-2024-3837",
    "CVE-2024-3838",
    "CVE-2024-3839",
    "CVE-2024-3840",
    "CVE-2024-3841",
    "CVE-2024-3843",
    "CVE-2024-3844",
    "CVE-2024-3845",
    "CVE-2024-3846",
    "CVE-2024-3847",
    "CVE-2024-3914"
  );
  script_xref(name:"IAVA", value:"2024-A-0248-S");

  script_name(english:"Google Chrome < 124.0.6367.60 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 124.0.6367.60. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_04_stable-channel-update-for-desktop_16 advisory.

  - Object corruption in V8 in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to potentially
    exploit object corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-3832)

  - Object corruption in WebAssembly in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to
    potentially exploit object corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-3833)

  - Use after free in V8 in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-3914)

  - Use after free in Downloads in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-3834)

  - Use after free in QUIC in Google Chrome prior to 124.0.6367.60 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2024-3837)

  - Inappropriate implementation in Autofill in Google Chrome prior to 124.0.6367.60 allowed an attacker who
    convinced a user to install a malicious app to perform UI spoofing via a crafted app. (Chromium security
    severity: Medium) (CVE-2024-3838)

  - Out of bounds read in Fonts in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2024-3839)

  - Insufficient policy enforcement in Site Isolation in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-3840)

  - Insufficient data validation in Browser Switcher in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to inject scripts or HTML into a privileged page via a malicious file. (Chromium security
    severity: Medium) (CVE-2024-3841)

  - Insufficient data validation in Downloads in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-3843)

  - Inappropriate implementation in Extensions in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to perform UI spoofing via a crafted Chrome Extension. (Chromium security severity: Low)
    (CVE-2024-3844)

  - Inappropriate implementation in Networks in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    to bypass mixed content policy via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-3845)

  - Inappropriate implementation in Prompts in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2024-3846)

  - Insufficient policy enforcement in WebUI in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    to bypass content security policy via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2024-3847)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/04/stable-channel-update-for-desktop_16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?843c08d5");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/331358160");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/331383939");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/326607008");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/41491379");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/328278717");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/41491859");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/41493458");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/330376742");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/330759272");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/41486690");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40058873");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/323583084");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40064754");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/328690293");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 124.0.6367.60 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3837");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/16");

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

google_chrome_check_version(installs:installs, fix:'124.0.6367.60', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
