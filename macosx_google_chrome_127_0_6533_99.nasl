#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205017);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/23");

  script_cve_id(
    "CVE-2024-7532",
    "CVE-2024-7533",
    "CVE-2024-7534",
    "CVE-2024-7535",
    "CVE-2024-7536",
    "CVE-2024-7550"
  );
  script_xref(name:"IAVA", value:"2024-A-0469-S");

  script_name(english:"Google Chrome < 127.0.6533.99 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 127.0.6533.99. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2024_08_stable-channel-update-for-desktop advisory.

  - Out of bounds memory access in ANGLE in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2024-7532)

  - Use after free in Sharing in Google Chrome on iOS prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7533)

  - Type Confusion in V8 in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-7550)

  - Heap buffer overflow in Layout in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7534)

  - Inappropriate implementation in V8 in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7535)

  - Use after free in WebAudio in Google Chrome prior to 127.0.6533.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-7536)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0048475");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/350528343");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/353552540");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/355256380");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/352467338");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/352690885");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/354847246");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 127.0.6533.99 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7550");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'127.0.6533.99', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
