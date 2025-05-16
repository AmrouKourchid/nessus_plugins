#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189461);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/20");

  script_cve_id(
    "CVE-2024-0804",
    "CVE-2024-0805",
    "CVE-2024-0806",
    "CVE-2024-0807",
    "CVE-2024-0808",
    "CVE-2024-0809",
    "CVE-2024-0810",
    "CVE-2024-0811",
    "CVE-2024-0812",
    "CVE-2024-0813",
    "CVE-2024-0814"
  );
  script_xref(name:"IAVA", value:"2024-A-0052-S");

  script_name(english:"Google Chrome < 121.0.6167.85 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 121.0.6167.85. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2024_01_stable-channel-update-for-desktop_23 advisory.

  - Use after free in Web Audio in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0807)

  - Inappropriate implementation in Accessibility in Google Chrome prior to 121.0.6167.85 allowed a remote
    attacker to potentially exploit object corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2024-0812)

  - Integer underflow in WebUI in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially exploit heap corruption via a malicious file. (Chromium security severity: High)
    (CVE-2024-0808)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 121.0.6167.85 allowed an attacker
    who convinced a user to install a malicious extension to leak cross-origin data via a crafted Chrome
    Extension. (Chromium security severity: Medium) (CVE-2024-0810)

  - Incorrect security UI in Payments in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-0814)

  - Use after free in Reading Mode in Google Chrome prior to 121.0.6167.85 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific UI interaction.
    (Chromium security severity: Medium) (CVE-2024-0813)

  - Use after free in Passwords in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially exploit heap corruption via specific UI interaction. (Chromium security severity: Medium)
    (CVE-2024-0806)

  - Inappropriate implementation in Downloads in Google Chrome prior to 121.0.6167.85 allowed a remote
    attacker to perform domain spoofing via a crafted domain name. (Chromium security severity: Medium)
    (CVE-2024-0805)

  - Insufficient policy enforcement in iOS Security UI in Google Chrome prior to 121.0.6167.85 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-0804)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 121.0.6167.85 allowed an attacker
    who convinced a user to install a malicious extension to leak cross-origin data via a crafted Chrome
    Extension. (Chromium security severity: Low) (CVE-2024-0811)

  - Inappropriate implementation in Autofill in Google Chrome prior to 121.0.6167.85 allowed a remote attacker
    to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-0809)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/01/stable-channel-update-for-desktop_23.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?682ca867");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1505080");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1484394");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1504936");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1496250");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1463935");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1477151");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1505176");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1514925");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1515137");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1494490");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1497985");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 121.0.6167.85 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0813");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-0808");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

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

google_chrome_check_version(fix:'121.0.6167.85', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
