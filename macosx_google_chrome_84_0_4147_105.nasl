#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139000);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2020-16046",
    "CVE-2020-6532",
    "CVE-2020-6537",
    "CVE-2020-6538",
    "CVE-2020-6539",
    "CVE-2020-6540",
    "CVE-2020-6541"
  );
  script_xref(name:"IAVA", value:"2020-A-0342-S");

  script_name(english:"Google Chrome < 84.0.4147.105 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 84.0.4147.105. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2020_07_stable-channel-update-for-desktop_27 advisory.

  - Type confusion in V8 in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to execute
    arbitrary code inside a sandbox via a crafted HTML page. (CVE-2020-6537)

  - Inappropriate implementation in WebView in Google Chrome on Android prior to 84.0.4147.105 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2020-6538)

  - Use after free in SCTP in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6532)

  - Use after free in CSS in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6539)

  - Buffer overflow in Skia in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6540)

  - Use after free in WebUSB in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6541)

  - Script injection in iOSWeb in Google Chrome on iOS prior to 84.0.4147.105 allowed a remote attacker to
    execute arbitrary code via a crafted HTML page. (CVE-2020-16046)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2020/07/stable-channel-update-for-desktop_27.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?356bbf62");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1105318");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1096677");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1098606");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1104061");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1105635");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1105720");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1106773");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1109361");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 84.0.4147.105 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6541");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'84.0.4147.105', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
