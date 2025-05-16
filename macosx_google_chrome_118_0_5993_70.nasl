#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182849);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/01");

  script_cve_id(
    "CVE-2023-5218",
    "CVE-2023-5473",
    "CVE-2023-5474",
    "CVE-2023-5475",
    "CVE-2023-5476",
    "CVE-2023-5477",
    "CVE-2023-5478",
    "CVE-2023-5479",
    "CVE-2023-5481",
    "CVE-2023-5483",
    "CVE-2023-5484",
    "CVE-2023-5485",
    "CVE-2023-5486",
    "CVE-2023-5487"
  );
  script_xref(name:"IAVA", value:"2023-A-0550-S");

  script_name(english:"Google Chrome < 118.0.5993.70 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 118.0.5993.70. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2023_10_stable-channel-update-for-desktop_10 advisory.

  - Use after free in Site Isolation. (CVE-2023-5218)

  - Use after free in Cast. (CVE-2023-5473)

  - Heap buffer overflow in PDF. (CVE-2023-5474)

  - Inappropriate implementation in DevTools. (CVE-2023-5475)

  - Use after free in Blink History. (CVE-2023-5476)

  - Inappropriate implementation in Installer. (CVE-2023-5477)

  - Inappropriate implementation in Autofill. (CVE-2023-5478, CVE-2023-5485)

  - Inappropriate implementation in Extensions API. (CVE-2023-5479)

  - Inappropriate implementation in Downloads. (CVE-2023-5481)

  - Inappropriate implementation in Intents. (CVE-2023-5483)

  - Inappropriate implementation in Navigation. (CVE-2023-5484)

  - Inappropriate implementation in Input. (CVE-2023-5486)

  - Inappropriate implementation in Fullscreen. (CVE-2023-5487)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/10/stable-channel-update-for-desktop_10.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57a1e6c0");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1487110");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1062251");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1414936");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1476952");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1425355");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1458934");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1474253");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1483194");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1471253");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1395164");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1472404");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1472558");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1357442");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1484000");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 118.0.5993.70 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/10");

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

google_chrome_check_version(fix:'118.0.5993.70', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
