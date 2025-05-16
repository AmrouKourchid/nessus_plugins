#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186363);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2023-6345",
    "CVE-2023-6346",
    "CVE-2023-6347",
    "CVE-2023-6348",
    "CVE-2023-6350",
    "CVE-2023-6351"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/21");
  script_xref(name:"IAVA", value:"2023-A-0660-S");

  script_name(english:"Google Chrome < 119.0.6045.199 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 119.0.6045.199. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_11_stable-channel-update-for-desktop_28 advisory.

  - Type Confusion in Spellcheck in Google Chrome prior to 119.0.6045.199 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-6348)

  - Use after free in Mojo in Google Chrome prior to 119.0.6045.199 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-6347)

  - Use after free in WebAudio in Google Chrome prior to 119.0.6045.199 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-6346)

  - Use after free in libavif in Google Chrome prior to 119.0.6045.199 allowed a remote attacker to
    potentially exploit heap corruption via a crafted avif file. (Chromium security severity: High)
    (CVE-2023-6350, CVE-2023-6351)

  - Integer overflow in Skia in Google Chrome prior to 119.0.6045.199 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a malicious file. (Chromium
    security severity: High) (CVE-2023-6345)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/11/stable-channel-update-for-desktop_28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be59469a");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1491459");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1494461");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1500856");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1501766");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1501770");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1505053");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 119.0.6045.199 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6351");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-6345");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'119.0.6045.199', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
