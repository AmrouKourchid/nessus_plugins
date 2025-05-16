#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142971);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2019-8075",
    "CVE-2020-16012",
    "CVE-2020-16014",
    "CVE-2020-16015",
    "CVE-2020-16018",
    "CVE-2020-16019",
    "CVE-2020-16020",
    "CVE-2020-16021",
    "CVE-2020-16022",
    "CVE-2020-16023",
    "CVE-2020-16024",
    "CVE-2020-16025",
    "CVE-2020-16026",
    "CVE-2020-16027",
    "CVE-2020-16028",
    "CVE-2020-16029",
    "CVE-2020-16030",
    "CVE-2020-16031",
    "CVE-2020-16032",
    "CVE-2020-16033",
    "CVE-2020-16034",
    "CVE-2020-16035",
    "CVE-2020-16036",
    "CVE-2020-16045"
  );
  script_xref(name:"IAVA", value:"2020-A-0533-S");

  script_name(english:"Google Chrome < 87.0.4280.66 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 87.0.4280.66. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2020_11_stable-channel-update-for-desktop_17 advisory.

  - Use after free in payments in Google Chrome prior to 87.0.4280.66 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-16018)

  - Inappropriate implementation in filesystem in Google Chrome on ChromeOS prior to 87.0.4280.66 allowed a
    remote attacker who had compromised the browser process to bypass noexec restrictions via a malicious
    file. (CVE-2020-16019)

  - Inappropriate implementation in cryptohome in Google Chrome on ChromeOS prior to 87.0.4280.66 allowed a
    remote attacker who had compromised the browser process to bypass discretionary access control via a
    malicious file. (CVE-2020-16020)

  - Race in image burner in Google Chrome on ChromeOS prior to 87.0.4280.66 allowed a remote attacker who had
    compromised the browser process to perform OS-level privilege escalation via a malicious file.
    (CVE-2020-16021)

  - Insufficient policy enforcement in networking in Google Chrome prior to 87.0.4280.66 allowed a remote
    attacker to potentially bypass firewall controls via a crafted HTML page. (CVE-2020-16022)

  - Insufficient data validation in WASM in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-16015)

  - Use after free in PPAPI in Google Chrome prior to 87.0.4280.66 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-16014)

  - Use after free in WebCodecs in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-16023)

  - Heap buffer overflow in UI in Google Chrome prior to 87.0.4280.66 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-16024)

  - Heap buffer overflow in clipboard in Google Chrome prior to 87.0.4280.66 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-16025)

  - Use after Free in Payments in Google Chrome on Android prior to 87.0.4280.66 allowed a remote attacker who
    had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-16045)

  - Use after free in WebRTC in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-16026)

  - Insufficient policy enforcement in developer tools in Google Chrome prior to 87.0.4280.66 allowed an
    attacker who convinced a user to install a malicious extension to obtain potentially sensitive information
    from the user's disk via a crafted Chrome Extension. (CVE-2020-16027)

  - Heap buffer overflow in WebRTC in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-16028)

  - Inappropriate implementation in PDFium in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to
    bypass navigation restrictions via a crafted PDF file. (CVE-2020-16029)

  - Insufficient data validation in Blink in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to
    inject arbitrary scripts or HTML (UXSS) via a crafted HTML page. (CVE-2020-16030)

  - Adobe Flash Player version 32.0.0.192 and earlier versions have a Same Origin Policy Bypass vulnerability.
    Successful exploitation could lead to Information Disclosure in the context of the current user.
    (CVE-2019-8075)

  - Insufficient data validation in UI in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to
    spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2020-16031)

  - Insufficient data validation in sharing in Google Chrome prior to 87.0.4280.66 allowed a remote attacker
    to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2020-16032)

  - Inappropriate implementation in WebUSB in Google Chrome prior to 87.0.4280.66 allowed a remote attacker to
    spoof security UI via a crafted HTML page. (CVE-2020-16033)

  - Inappropriate implementation in WebRTC in Google Chrome prior to 87.0.4280.66 allowed a local attacker to
    bypass policy restrictions via a crafted HTML page. (CVE-2020-16034)

  - Insufficient data validation in cros-disks in Google Chrome on ChromeOS prior to 87.0.4280.66 allowed a
    remote attacker who had compromised the browser process to bypass noexec restrictions via a malicious
    file. (CVE-2020-16035)

  - Side-channel information leakage in graphics in Google Chrome prior to 87.0.4280.66 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2020-16012)

  - Inappropriate implementation in cookies in Google Chrome prior to 87.0.4280.66 allowed a remote attacker
    to bypass cookie restrictions via a crafted HTML page. (CVE-2020-16036)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1088224");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1116444");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1125614");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1133183");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1134338");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1136078");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1136714");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1137362");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1138446");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1139153");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1139408");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1139409");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1139411");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1139414");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1141350");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1143057");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1145680");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1146673");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1146675");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1146761");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1147430");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1147431");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/830808");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/945997");
  # https://chromereleases.googleblog.com/2020/11/stable-channel-update-for-desktop_17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?094cd655");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 87.0.4280.66 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16045");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'87.0.4280.66', severity:SECURITY_WARNING, xss:TRUE, xsrf:FALSE);
