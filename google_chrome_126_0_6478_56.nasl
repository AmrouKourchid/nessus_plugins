#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200329);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id(
    "CVE-2024-5830",
    "CVE-2024-5831",
    "CVE-2024-5832",
    "CVE-2024-5833",
    "CVE-2024-5834",
    "CVE-2024-5835",
    "CVE-2024-5836",
    "CVE-2024-5837",
    "CVE-2024-5838",
    "CVE-2024-5839",
    "CVE-2024-5840",
    "CVE-2024-5841",
    "CVE-2024-5842",
    "CVE-2024-5843",
    "CVE-2024-5844",
    "CVE-2024-5845",
    "CVE-2024-5846",
    "CVE-2024-5847"
  );
  script_xref(name:"IAVA", value:"2024-A-0354-S");

  script_name(english:"Google Chrome < 126.0.6478.56 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 126.0.6478.56. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_06_stable-channel-update-for-desktop advisory.

  - Type Confusion in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to perform an out
    of bounds memory write via a crafted HTML page. (Chromium security severity: High) (CVE-2024-5830)

  - Use after free in Dawn in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-5831)

  - Type Confusion in V8 in Google Chrome prior to 126.0.6478.54 allowed a remote attacker to potentially
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-5833)

  - Inappropriate implementation in Downloads in Google Chrome prior to 126.0.6478.54 allowed a remote
    attacker to obfuscate security UI via a malicious file. (Chromium security severity: Medium)
    (CVE-2024-5843)

  - Use after free in Dawn. (CVE-2024-5832)

  - Inappropriate implementation in Dawn. (CVE-2024-5834)

  - Heap buffer overflow in Tab Groups. (CVE-2024-5835)

  - Inappropriate Implementation in DevTools. (CVE-2024-5836)

  - Type Confusion in V8. (CVE-2024-5837, CVE-2024-5838)

  - Inappropriate Implementation in Memory Allocator. (CVE-2024-5839)

  - Policy Bypass in CORS. (CVE-2024-5840)

  - Use after free in V8. (CVE-2024-5841)

  - Use after free in Browser UI. (CVE-2024-5842)

  - Heap buffer overflow in Tab Strip. (CVE-2024-5844)

  - Use after free in Audio. (CVE-2024-5845)

  - Use after free in PDFium. (CVE-2024-5846, CVE-2024-5847)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/06/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?534c3d99");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/342456991");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/339171223");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/340196361");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/342602616");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/342840932");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/341991535");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/341875171");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/342415789");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/342522151");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/340122160");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/41492103");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/326765855");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40062622");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/333940412");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/331960660");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/340178596");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/341095523");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/341313077");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 126.0.6478.56 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

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

google_chrome_check_version(installs:installs, fix:'126.0.6478.56', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
