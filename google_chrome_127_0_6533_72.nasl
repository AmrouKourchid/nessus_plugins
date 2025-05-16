#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(203498);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id(
    "CVE-2024-6988",
    "CVE-2024-6989",
    "CVE-2024-6991",
    "CVE-2024-6994",
    "CVE-2024-6995",
    "CVE-2024-6996",
    "CVE-2024-6997",
    "CVE-2024-6998",
    "CVE-2024-6999",
    "CVE-2024-7000",
    "CVE-2024-7001",
    "CVE-2024-7003",
    "CVE-2024-7004",
    "CVE-2024-7005"
  );
  script_xref(name:"IAVA", value:"2024-A-0441-S");
  script_xref(name:"IAVA", value:"2024-A-0452-S");

  script_name(english:"Google Chrome < 127.0.6533.72 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 127.0.6533.72. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_07_stable-channel-update-for-desktop_23 advisory.

  - Use after free in Downloads. (CVE-2024-6988)

  - Use after free in Loader. (CVE-2024-6989)

  - Use after free in Dawn. (CVE-2024-6991)

  - Heap buffer overflow in Layout. (CVE-2024-6994)

  - Inappropriate implementation in Fullscreen. (CVE-2024-6995)

  - Use after free in Tabs. (CVE-2024-6997)

  - Use after free in User Education. (CVE-2024-6998)

  - Inappropriate implementation in FedCM. (CVE-2024-6999, CVE-2024-7003)

  - Use after free in CSS. (CVE-2024-7000)

  - Inappropriate implementation in HTML. (CVE-2024-7001)

  - Insufficient validation of untrusted input in Safe Browsing. (CVE-2024-7004, CVE-2024-7005)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/07/stable-channel-update-for-desktop_23.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00feb124");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/349198731");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/349342289");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/346618785");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/339686368");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/343938078");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/333708039");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/325293263");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/340098902");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/340893685");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/339877158");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/347509736");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/338233148");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40063014");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40068800");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 127.0.6533.72 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/23");

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

google_chrome_check_version(installs:installs, fix:'127.0.6533.72', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
