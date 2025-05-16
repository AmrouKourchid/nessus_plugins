#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119558);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/24");

  script_cve_id(
    "CVE-2018-17480",
    "CVE-2018-17481",
    "CVE-2018-18335",
    "CVE-2018-18336",
    "CVE-2018-18337",
    "CVE-2018-18338",
    "CVE-2018-18339",
    "CVE-2018-18340",
    "CVE-2018-18341",
    "CVE-2018-18342",
    "CVE-2018-18343",
    "CVE-2018-18344",
    "CVE-2018-18345",
    "CVE-2018-18346",
    "CVE-2018-18347",
    "CVE-2018-18348",
    "CVE-2018-18349",
    "CVE-2018-18350",
    "CVE-2018-18351",
    "CVE-2018-18352",
    "CVE-2018-18353",
    "CVE-2018-18354",
    "CVE-2018-18355",
    "CVE-2018-18356",
    "CVE-2018-18357",
    "CVE-2018-18358",
    "CVE-2018-18359",
    "CVE-2018-20065",
    "CVE-2018-20066",
    "CVE-2018-20067",
    "CVE-2018-20068",
    "CVE-2018-20069",
    "CVE-2018-20070",
    "CVE-2018-20071"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Google Chrome < 71.0.3578.80 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 71.0.3578.80. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2018_12_stable-channel-update-for-desktop advisory.

  - Execution of user supplied Javascript during array deserialization leading to an out of bounds write in V8
    in Google Chrome prior to 71.0.3578.80 allowed a remote attacker to execute arbitrary code inside a
    sandbox via a crafted HTML page. (CVE-2018-17480)

  - Incorrect object lifecycle handling in PDFium in Google Chrome prior to 71.0.3578.98 allowed a remote
    attacker to potentially exploit heap corruption via a crafted PDF file. (CVE-2018-17481)

  - Heap buffer overflow in Skia in Google Chrome prior to 71.0.3578.80 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2018-18335)

  - Incorrect object lifecycle in PDFium in Google Chrome prior to 71.0.3578.80 allowed a remote attacker to
    potentially exploit heap corruption via a crafted PDF file. (CVE-2018-18336)

  - Incorrect handling of stylesheets leading to a use after free in Blink in Google Chrome prior to
    71.0.3578.80 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2018-18337)

  - Incorrect, thread-unsafe use of SkImage in Canvas in Google Chrome prior to 71.0.3578.80 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2018-18338)

  - Incorrect object lifecycle in WebAudio in Google Chrome prior to 71.0.3578.80 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2018-18339)

  - Incorrect object lifecycle in MediaRecorder in Google Chrome prior to 71.0.3578.80 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2018-18340)

  - An integer overflow leading to a heap buffer overflow in Blink in Google Chrome prior to 71.0.3578.80
    allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2018-18341)

  - Execution of user supplied Javascript during object deserialization can update object length leading to an
    out of bounds write in V8 in Google Chrome prior to 71.0.3578.80 allowed a remote attacker to execute
    arbitrary code inside a sandbox via a crafted HTML page. (CVE-2018-18342)

  - Incorrect handing of paths leading to a use after free in Skia in Google Chrome prior to 71.0.3578.80
    allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2018-18343)

  - Inappropriate allowance of the setDownloadBehavior devtools protocol feature in Extensions in Google
    Chrome prior to 71.0.3578.80 allowed a remote attacker with control of an installed extension to access
    files on the local file system via a crafted Chrome Extension. (CVE-2018-18344)

  - Incorrect handling of blob URLS in Site Isolation in Google Chrome prior to 71.0.3578.80 allowed a remote
    attacker who had compromised the renderer process to bypass site isolation protections via a crafted HTML
    page. (CVE-2018-18345)

  - Incorrect handling of alert box display in Blink in Google Chrome prior to 71.0.3578.80 allowed a remote
    attacker to present confusing browser UI via a crafted HTML page. (CVE-2018-18346)

  - Incorrect handling of failed navigations with invalid URLs in Navigation in Google Chrome prior to
    71.0.3578.80 allowed a remote attacker to trick a user into executing javascript in an arbitrary origin
    via a crafted HTML page. (CVE-2018-18347)

  - Incorrect handling of bidirectional domain names with RTL characters in Omnibox in Google Chrome prior to
    71.0.3578.80 allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted domain
    name. (CVE-2018-18348)

  - Remote frame navigations was incorrectly permitted to local resources in Blink in Google Chrome prior to
    71.0.3578.80 allowed an attacker who convinced a user to install a malicious extension to access files on
    the local file system via a crafted Chrome Extension. (CVE-2018-18349)

  - Incorrect handling of CSP enforcement during navigations in Blink in Google Chrome prior to 71.0.3578.80
    allowed a remote attacker to bypass content security policy via a crafted HTML page. (CVE-2018-18350)

  - Lack of proper validation of ancestor frames site when sending lax cookies in Navigation in Google Chrome
    prior to 71.0.3578.80 allowed a remote attacker to bypass SameSite cookie policy via a crafted HTML page.
    (CVE-2018-18351)

  - Service works could inappropriately gain access to cross origin audio in Media in Google Chrome prior to
    71.0.3578.80 allowed a remote attacker to bypass same origin policy for audio content via a crafted HTML
    page. (CVE-2018-18352)

  - Failure to dismiss http auth dialogs on navigation in Network Authentication in Google Chrome on Android
    prior to 71.0.3578.80 allowed a remote attacker to confuse the user about the origin of an auto dialog via
    a crafted HTML page. (CVE-2018-18353)

  - Insufficient validate of external protocols in Shell Integration in Google Chrome on Windows prior to
    71.0.3578.80 allowed a remote attacker to launch external programs via a crafted HTML page.
    (CVE-2018-18354)

  - Incorrect handling of confusable characters in URL Formatter in Google Chrome prior to 71.0.3578.80
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted domain name.
    (CVE-2018-18355, CVE-2018-18357, CVE-2018-20070)

  - An integer overflow in path handling lead to a use after free in Skia in Google Chrome prior to
    71.0.3578.80 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2018-18356)

  - Lack of special casing of localhost in WPAD files in Google Chrome prior to 71.0.3578.80 allowed an
    attacker on the local network segment to proxy resources on localhost via a crafted WPAD file.
    (CVE-2018-18358)

  - Incorrect handling of Reflect.construct in V8 in Google Chrome prior to 71.0.3578.80 allowed a remote
    attacker to perform an out of bounds memory read via a crafted HTML page. (CVE-2018-18359)

  - Handling of URI action in PDFium in Google Chrome prior to 71.0.3578.80 allowed a remote attacker to
    initiate potentially unsafe navigations without a user gesture via a crafted PDF file. (CVE-2018-20065)

  - Incorrect object lifecycle in Extensions in Google Chrome prior to 71.0.3578.80 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (CVE-2018-20066)

  - A renderer initiated back navigation was incorrectly allowed to cancel a browser initiated one in
    Navigation in Google Chrome prior to 71.0.3578.80 allowed a remote attacker to confuse the user about the
    origin of the current page via a crafted HTML page. (CVE-2018-20067)

  - Incorrect handling of 304 status codes in Navigation in Google Chrome prior to 71.0.3578.80 allowed a
    remote attacker to confuse the user about the origin of the current page via a crafted HTML page.
    (CVE-2018-20068)

  - Failure to prevent navigation to top frame to data URLs in Navigation in Google Chrome on iOS prior to
    71.0.3578.80 allowed a remote attacker to confuse the user about the origin of the current page via a
    crafted HTML page. (CVE-2018-20069)

  - Insufficiently strict origin checks during JIT payment app installation in Payments in Google Chrome prior
    to 70.0.3538.67 allowed a remote attacker to install a service worker for a domain that can host attacker
    controled files via a crafted HTML page. (CVE-2018-20071)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?084b0392");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/606104");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/799747");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/833847");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/849942");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/850824");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/851821");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/853937");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/856135");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/866426");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/879965");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/881659");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/882270");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/882423");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/883666");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/884179");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/886753");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/886976");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/889459");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/890558");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/890576");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/891187");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/894399");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/895207");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/895362");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/895885");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/896717");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/896736");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/898531");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/899126");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/900910");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/901030");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/901654");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/905940");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/906313");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/907714");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 71.0.3578.80 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20066");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'71.0.3578.80', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
