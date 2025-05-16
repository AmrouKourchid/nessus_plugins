#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233671);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2025-3067",
    "CVE-2025-3068",
    "CVE-2025-3069",
    "CVE-2025-3070",
    "CVE-2025-3071",
    "CVE-2025-3072",
    "CVE-2025-3073",
    "CVE-2025-3074"
  );
  script_xref(name:"IAVA", value:"2025-A-0214-S");

  script_name(english:"Google Chrome < 135.0.7049.41 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 135.0.7049.41. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2025_04_stable-channel-update-for-desktop advisory.

  - Inappropriate implementation in Downloads in Google Chrome prior to 135.0.7049.52 allowed a remote
    attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Low) (CVE-2025-3074)

  - Inappropriate implementation in Extensions in Google Chrome prior to 135.0.7049.52 allowed a remote
    attacker to perform privilege escalation via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2025-3069)

  - Inappropriate implementation in Custom Tabs in Google Chrome on Android prior to 135.0.7049.52 allowed a
    remote attacker who convinced a user to engage in specific UI gestures to perform privilege escalation via
    a crafted app. (Chromium security severity: Medium) (CVE-2025-3067)

  - Inappropriate implementation in Intents in Google Chrome on Android prior to 135.0.7049.52 allowed a
    remote attacker to perform privilege escalation via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2025-3068)

  - Insufficient validation of untrusted input in Extensions in Google Chrome prior to 135.0.7049.52 allowed a
    remote attacker to perform privilege escalation via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2025-3070)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2025/04/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4aed73f8");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/376491759");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/401823929");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40060076");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40086360");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40051596");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/362545037");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/388680893");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/392818696");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 135.0.7049.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-3074");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-3069");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

google_chrome_check_version(installs:installs, fix:'135.0.7049.41', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
