##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163725);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/24");

  script_cve_id(
    "CVE-2022-2603",
    "CVE-2022-2604",
    "CVE-2022-2605",
    "CVE-2022-2606",
    "CVE-2022-2607",
    "CVE-2022-2608",
    "CVE-2022-2609",
    "CVE-2022-2610",
    "CVE-2022-2611",
    "CVE-2022-2612",
    "CVE-2022-2613",
    "CVE-2022-2614",
    "CVE-2022-2615",
    "CVE-2022-2616",
    "CVE-2022-2617",
    "CVE-2022-2618",
    "CVE-2022-2619",
    "CVE-2022-2620",
    "CVE-2022-2621",
    "CVE-2022-2622",
    "CVE-2022-2623",
    "CVE-2022-2624",
    "CVE-2022-2742",
    "CVE-2022-2743",
    "CVE-2022-4914"
  );
  script_xref(name:"IAVA", value:"2022-A-0304-S");

  script_name(english:"Google Chrome < 104.0.5112.79 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 104.0.5112.79. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2022_08_stable-channel-update-for-desktop advisory.

  - Use after free in Omnibox in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2603)

  - Use after free in Safe Browsing in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2604)

  - Out of bounds read in Dawn in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2605)

  - Use after free in Managed devices API in Google Chrome prior to 104.0.5112.79 allowed a remote attacker
    who convinced a user to enable a specific Enterprise policy to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-2606)

  - Use after free in Tab Strip in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker
    who convinced a user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2607)

  - Use after free in Overview Mode in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote
    attacker who convinced a user to engage in specific user interactions to potentially exploit heap
    corruption via specific UI interactions. (CVE-2022-2608)

  - Use after free in Nearby Share in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote
    attacker who convinced a user to engage in specific user interactions to potentially exploit heap
    corruption via specific UI interactions. (CVE-2022-2609)

  - Use after free in Exosphere in Google Chrome on Chrome OS and Lacros prior to 104.0.5112.79 allowed a
    remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap
    corruption via crafted UI interactions. (Chrome security severity: High) (CVE-2022-2742)

  - Integer overflow in Window Manager in Google Chrome on Chrome OS and Lacros prior to 104.0.5112.79 allowed
    a remote attacker who convinced a user to engage in specific UI interactions to perform an out of bounds
    memory write via crafted UI interactions. (Chrome security severity: High) (CVE-2022-2743)

  - Insufficient policy enforcement in Background Fetch in Google Chrome prior to 104.0.5112.79 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-2610)

  - Inappropriate implementation in Fullscreen API in Google Chrome on Android prior to 104.0.5112.79 allowed
    a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-2611)

  - Side-channel information leakage in Keyboard input in Google Chrome prior to 104.0.5112.79 allowed a
    remote attacker who had compromised the renderer process to obtain potentially sensitive information from
    process memory via a crafted HTML page. (CVE-2022-2612)

  - Use after free in Input in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to enage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2613)

  - Use after free in Sign-In Flow in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2614)

  - Heap buffer overflow in PrintPreview in Google Chrome prior to 104.0.5112.79 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2022-4914)

  - Insufficient policy enforcement in Cookies in Google Chrome prior to 104.0.5112.79 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-2615)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 104.0.5112.79 allowed an attacker
    who convinced a user to install a malicious extension to spoof the contents of the Omnibox (URL bar) via a
    crafted Chrome Extension. (CVE-2022-2616)

  - Use after free in Extensions API in Google Chrome prior to 104.0.5112.79 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via specific UI
    interactions. (CVE-2022-2617)

  - Insufficient validation of untrusted input in Internals in Google Chrome prior to 104.0.5112.79 allowed a
    remote attacker to bypass download restrictions via a malicious file . (CVE-2022-2618)

  - Insufficient validation of untrusted input in Settings in Google Chrome prior to 104.0.5112.79 allowed an
    attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged
    page via a crafted HTML page. (CVE-2022-2619)

  - Use after free in WebUI in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2620)

  - Use after free in Extensions in Google Chrome prior to 104.0.5112.79 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific UI interactions.
    (CVE-2022-2621)

  - Insufficient validation of untrusted input in Safe Browsing in Google Chrome on Windows prior to
    104.0.5112.79 allowed a remote attacker to bypass download restrictions via a crafted file.
    (CVE-2022-2622)

  - Use after free in Offline in Google Chrome on Android prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2623)

  - Heap buffer overflow in PDF in Google Chrome prior to 104.0.5112.79 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via a
    crafted PDF file. (CVE-2022-2624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/08/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?806fe022");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1232402");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1325699");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1335316");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1338470");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1330489");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1286203");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1330775");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1338560");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1278255");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1320538");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1321350");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1325256");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1341907");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1268580");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1302159");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1292451");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1308422");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1316960");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1319172");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1332881");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1337304");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1323449");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1332392");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1337798");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1339745");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 104.0.5112.79 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4914");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'104.0.5112.79', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
