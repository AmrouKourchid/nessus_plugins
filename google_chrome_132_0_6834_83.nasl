#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214138);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/22");

  script_cve_id(
    "CVE-2025-0434",
    "CVE-2025-0435",
    "CVE-2025-0436",
    "CVE-2025-0437",
    "CVE-2025-0438",
    "CVE-2025-0439",
    "CVE-2025-0440",
    "CVE-2025-0441",
    "CVE-2025-0442",
    "CVE-2025-0443",
    "CVE-2025-0446",
    "CVE-2025-0447",
    "CVE-2025-0448"
  );
  script_xref(name:"IAVA", value:"2025-A-0010-S");

  script_name(english:"Google Chrome < 132.0.6834.83 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 132.0.6834.83. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2025_01_stable-channel-update-for-desktop_14 advisory.

  - Inappropriate implementation in Compositing. (CVE-2025-0448)

  - Out of bounds memory access in V8. (CVE-2025-0434)

  - Inappropriate implementation in Navigation. (CVE-2025-0435, CVE-2025-0447)

  - Integer overflow in Skia. (CVE-2025-0436)

  - Out of bounds read in Metrics. (CVE-2025-0437)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2025/01/stable-channel-update-for-desktop_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3db8c3b6");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/374627491");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/379652406");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/382786791");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/378623799");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/384186539");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/371247941");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40067914");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/368628042");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40940854");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/376625003");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/359949844");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/375550814");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/377948403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 132.0.6834.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0437");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

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

google_chrome_check_version(installs:installs, fix:'132.0.6834.83', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
