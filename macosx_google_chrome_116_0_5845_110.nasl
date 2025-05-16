#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180162);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2023-4427",
    "CVE-2023-4428",
    "CVE-2023-4429",
    "CVE-2023-4430",
    "CVE-2023-4431"
  );
  script_xref(name:"IAVA", value:"2023-A-0447-S");

  script_name(english:"Google Chrome < 116.0.5845.110 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 116.0.5845.110. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_08_chrome-desktop-stable-update advisory.

  - Use after free in Vulkan in Google Chrome prior to 116.0.5845.110 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4430)

  - Use after free in Loader in Google Chrome prior to 116.0.5845.110 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4429)

  - Out of bounds memory access in CSS in Google Chrome prior to 116.0.5845.110 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4428)

  - Out of bounds memory access in V8 in Google Chrome prior to 116.0.5845.110 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4427)

  - Out of bounds memory access in Fonts in Google Chrome prior to 116.0.5845.110 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4431)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/08/chrome-desktop-stable-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?839a3ccf");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1469542");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1469754");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1470477");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1470668");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1469348");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 116.0.5845.110 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4430");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'116.0.5845.110', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
