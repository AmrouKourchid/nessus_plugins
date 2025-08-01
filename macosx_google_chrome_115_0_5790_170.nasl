#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179225);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/17");

  script_cve_id(
    "CVE-2023-4068",
    "CVE-2023-4069",
    "CVE-2023-4070",
    "CVE-2023-4071",
    "CVE-2023-4072",
    "CVE-2023-4073",
    "CVE-2023-4074",
    "CVE-2023-4075",
    "CVE-2023-4076",
    "CVE-2023-4077",
    "CVE-2023-4078"
  );
  script_xref(name:"IAVA", value:"2023-A-0387-S");

  script_name(english:"Google Chrome < 115.0.5790.170 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 115.0.5790.170. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_08_stable-channel-update-for-desktop advisory.

  - Type Confusion in V8. (CVE-2023-4068, CVE-2023-4069, CVE-2023-4070)

  - Heap buffer overflow in Visuals. (CVE-2023-4071)

  - Out of bounds read and write in WebGL. (CVE-2023-4072)

  - Out of bounds memory access in ANGLE. (CVE-2023-4073)

  - Use after free in Blink Task Scheduling. (CVE-2023-4074)

  - Use after free in Cast. (CVE-2023-4075)

  - Use after free in WebRTC. (CVE-2023-4076)

  - Insufficient data validation in Extensions. (CVE-2023-4077)

  - Inappropriate implementation in Extensions. (CVE-2023-4078)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/08/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4fb4693a");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1466183");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1465326");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1462951");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1458819");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1464038");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1456243");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1464113");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1457757");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1459124");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1451146");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1461895");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 115.0.5790.170 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/02");

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

google_chrome_check_version(fix:'115.0.5790.170', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
