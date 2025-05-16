#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202309-17.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(182402);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/23");

  script_cve_id(
    "CVE-2023-0696",
    "CVE-2023-0697",
    "CVE-2023-0698",
    "CVE-2023-0699",
    "CVE-2023-0700",
    "CVE-2023-0701",
    "CVE-2023-0702",
    "CVE-2023-0703",
    "CVE-2023-0704",
    "CVE-2023-0705",
    "CVE-2023-0927",
    "CVE-2023-0928",
    "CVE-2023-0929",
    "CVE-2023-0930",
    "CVE-2023-0931",
    "CVE-2023-0932",
    "CVE-2023-0933",
    "CVE-2023-0941",
    "CVE-2023-1528",
    "CVE-2023-1529",
    "CVE-2023-1530",
    "CVE-2023-1531",
    "CVE-2023-1532",
    "CVE-2023-1533",
    "CVE-2023-1534",
    "CVE-2023-1810",
    "CVE-2023-1811",
    "CVE-2023-1812",
    "CVE-2023-1813",
    "CVE-2023-1814",
    "CVE-2023-1815",
    "CVE-2023-1816",
    "CVE-2023-1817",
    "CVE-2023-1818",
    "CVE-2023-1819",
    "CVE-2023-1820",
    "CVE-2023-1821",
    "CVE-2023-1822",
    "CVE-2023-1823",
    "CVE-2023-2033",
    "CVE-2023-2133",
    "CVE-2023-2134",
    "CVE-2023-2135",
    "CVE-2023-2136",
    "CVE-2023-2137",
    "CVE-2023-2459",
    "CVE-2023-2460",
    "CVE-2023-2461",
    "CVE-2023-2462",
    "CVE-2023-2463",
    "CVE-2023-2464",
    "CVE-2023-2465",
    "CVE-2023-2466",
    "CVE-2023-2467",
    "CVE-2023-2468",
    "CVE-2023-2721",
    "CVE-2023-2722",
    "CVE-2023-2723",
    "CVE-2023-2724",
    "CVE-2023-2725",
    "CVE-2023-2726",
    "CVE-2023-21720",
    "CVE-2023-21794",
    "CVE-2023-23374",
    "CVE-2023-28261",
    "CVE-2023-28286",
    "CVE-2023-29334",
    "CVE-2023-29350",
    "CVE-2023-29354"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/08");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/12");

  script_name(english:"GLSA-202309-17 : Chromium, Google Chrome, Microsoft Edge: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202309-17 (Chromium, Google Chrome, Microsoft Edge:
Multiple Vulnerabilities)

  - Type confusion in V8 in Google Chrome prior to 110.0.5481.77 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0696)

  - Inappropriate implementation in Full screen mode in Google Chrome on Android prior to 110.0.5481.77
    allowed a remote attacker to spoof the contents of the security UI via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-0697)

  - Out of bounds read in WebRTC in Google Chrome prior to 110.0.5481.77 allowed a remote attacker to perform
    an out of bounds memory read via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0698)

  - Use after free in GPU in Google Chrome prior to 110.0.5481.77 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page and browser shutdown. (Chromium security severity: Medium)
    (CVE-2023-0699)

  - Inappropriate implementation in Download in Google Chrome prior to 110.0.5481.77 allowed a remote attacker
    to potentially spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-0700)

  - Heap buffer overflow in WebUI in Google Chrome prior to 110.0.5481.77 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via UI
    interaction . (Chromium security severity: Medium) (CVE-2023-0701)

  - Type confusion in Data Transfer in Google Chrome prior to 110.0.5481.77 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-0702)

  - Type confusion in DevTools in Google Chrome prior to 110.0.5481.77 allowed a remote attacker who convinced
    a user to engage in specific UI interactions to potentially exploit heap corruption via UI interactions.
    (Chromium security severity: Medium) (CVE-2023-0703)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 110.0.5481.77 allowed a remote
    attacker to bypass same origin policy and proxy settings via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0704)

  - Integer overflow in Core in Google Chrome prior to 110.0.5481.77 allowed a remote attacker who had one a
    race condition to potentially exploit heap corruption via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0705)

  - Use after free in Web Payments API in Google Chrome on Android prior to 110.0.5481.177 allowed a remote
    attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: High) (CVE-2023-0927)

  - Use after free in SwiftShader in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-0928)

  - Use after free in Vulkan in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0929)

  - Heap buffer overflow in Video in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-0930)

  - Use after free in Video in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0931)

  - Use after free in WebRTC in Google Chrome on Windows prior to 110.0.5481.177 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2023-0932)

  - Integer overflow in PDF in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: Medium) (CVE-2023-0933)

  - Use after free in Prompts in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-0941)

  - Use after free in Passwords in Google Chrome prior to 111.0.5563.110 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1528)

  - Out of bounds memory access in WebHID in Google Chrome prior to 111.0.5563.110 allowed a remote attacker
    to potentially exploit heap corruption via a malicious HID device. (Chromium security severity: High)
    (CVE-2023-1529)

  - Use after free in PDF in Google Chrome prior to 111.0.5563.110 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1530)

  - Use after free in ANGLE in Google Chrome prior to 111.0.5563.110 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1531)

  - Out of bounds read in GPU Video in Google Chrome prior to 111.0.5563.110 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-1532)

  - Use after free in WebProtect in Google Chrome prior to 111.0.5563.110 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-1533)

  - Out of bounds read in ANGLE in Google Chrome prior to 111.0.5563.110 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1534)

  - Heap buffer overflow in Visuals in Google Chrome prior to 112.0.5615.49 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1810)

  - Use after free in Frames in Google Chrome prior to 112.0.5615.49 allowed a remote attacker who convinced a
    user to engage in specific UI interaction to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-1811)

  - Out of bounds memory access in DOM Bindings in Google Chrome prior to 112.0.5615.49 allowed a remote
    attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1812)

  - Inappropriate implementation in Extensions in Google Chrome prior to 112.0.5615.49 allowed an attacker who
    convinced a user to install a malicious extension to bypass file access restrictions via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-1813)

  - Insufficient validation of untrusted input in Safe Browsing in Google Chrome prior to 112.0.5615.49
    allowed a remote attacker to bypass download checking via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-1814)

  - Use after free in Networking APIs in Google Chrome prior to 112.0.5615.49 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-1815)

  - Incorrect security UI in Picture In Picture in Google Chrome prior to 112.0.5615.49 allowed a remote
    attacker to potentially perform navigation spoofing via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1816)

  - Insufficient policy enforcement in Intents in Google Chrome on Android prior to 112.0.5615.49 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1817)

  - Use after free in Vulkan in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-1818)

  - Out of bounds read in Accessibility in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1819)

  - Heap buffer overflow in Browser History in Google Chrome prior to 112.0.5615.49 allowed a remote attacker
    who convinced a user to engage in specific UI interaction to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-1820)

  - Inappropriate implementation in WebShare in Google Chrome prior to 112.0.5615.49 allowed a remote attacker
    to potentially hide the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-1821)

  - Incorrect security UI in Navigation in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to
    perform domain spoofing via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-1822)

  - Inappropriate implementation in FedCM in Google Chrome prior to 112.0.5615.49 allowed a remote attacker to
    bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-1823)

  - Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-2033)

  - Out of bounds memory access in Service Worker API in Google Chrome prior to 112.0.5615.137 allowed a
    remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security
    severity: High) (CVE-2023-2133, CVE-2023-2134)

  - Use after free in DevTools in Google Chrome prior to 112.0.5615.137 allowed a remote attacker who
    convinced a user to enable specific preconditions to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: High) (CVE-2023-2135)

  - Integer overflow in Skia in Google Chrome prior to 112.0.5615.137 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2136)

  - Heap buffer overflow in sqlite in Google Chrome prior to 112.0.5615.137 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-2137)

  - Inappropriate implementation in Prompts in Google Chrome prior to 113.0.5672.63 allowed a remote attacker
    to bypass permission restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-2459)

  - Insufficient validation of untrusted input in Extensions in Google Chrome prior to 113.0.5672.63 allowed
    an attacker who convinced a user to install a malicious extension to bypass file access checks via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-2460)

  - Use after free in OS Inputs in Google Chrome on ChromeOS prior to 113.0.5672.63 allowed a remote attacker
    who convinced a user to enage in specific UI interaction to potentially exploit heap corruption via
    crafted UI interaction. (Chromium security severity: Medium) (CVE-2023-2461)

  - Inappropriate implementation in Prompts in Google Chrome prior to 113.0.5672.63 allowed a remote attacker
    to obfuscate main origin data via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-2462)

  - Inappropriate implementation in Full Screen Mode in Google Chrome on Android prior to 113.0.5672.63
    allowed a remote attacker to hide the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-2463)

  - Inappropriate implementation in PictureInPicture in Google Chrome prior to 113.0.5672.63 allowed an
    attacker who convinced a user to install a malicious extension to perform an origin spoof in the security
    UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-2464)

  - Inappropriate implementation in CORS in Google Chrome prior to 113.0.5672.63 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-2465)

  - Inappropriate implementation in Prompts in Google Chrome prior to 113.0.5672.63 allowed a remote attacker
    to spoof the contents of the security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-2466)

  - Inappropriate implementation in Prompts in Google Chrome on Android prior to 113.0.5672.63 allowed a
    remote attacker to bypass permissions restrictions via a crafted HTML page. (Chromium security severity:
    Low) (CVE-2023-2467)

  - Inappropriate implementation in PictureInPicture in Google Chrome prior to 113.0.5672.63 allowed a remote
    attacker who had compromised the renderer process to obfuscate the security UI via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2023-2468)

  - Use after free in Navigation in Google Chrome prior to 113.0.5672.126 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-2721)

  - Use after free in Autofill UI in Google Chrome on Android prior to 113.0.5672.126 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2023-2722)

  - Use after free in DevTools in Google Chrome prior to 113.0.5672.126 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-2723)

  - Type confusion in V8 in Google Chrome prior to 113.0.5672.126 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-2724)

  - Use after free in Guest View in Google Chrome prior to 113.0.5672.126 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2725)

  - Inappropriate implementation in WebApp Installs in Google Chrome prior to 113.0.5672.126 allowed an
    attacker who convinced a user to install a malicious web app to bypass install dialog via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-2726)

  - Microsoft Edge (Chromium-based) Tampering Vulnerability (CVE-2023-21720)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2023-21794, CVE-2023-29334)

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability (CVE-2023-23374)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability (CVE-2023-28261, CVE-2023-29350)

  - Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability (CVE-2023-28286, CVE-2023-29354)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202309-17");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=893660");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=904252");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=904394");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=904560");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=905297");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=905620");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=905883");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=906586");
  script_set_attribute(attribute:"solution", value:
"All Chromium users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-113.0.5672.126
        
All Google Chrome users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/google-chrome-113.0.5672.126
        
All Microsoft Edge users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/microsoft-edge-113.0.1774.50
        
Gentoo has discontinued support for www-client/chromium-bin. Users should unmerge it in favor of the above alternatives:

          # emerge --ask --depclean --verbose www-client/chromium-bin");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2726");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1529");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:microsoft-edge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'www-client/chromium',
    'unaffected' : make_list("ge 113.0.5672.126"),
    'vulnerable' : make_list("lt 113.0.5672.126")
  },
  {
    'name' : 'www-client/google-chrome',
    'unaffected' : make_list("ge 113.0.5672.126"),
    'vulnerable' : make_list("lt 113.0.5672.126")
  },
  {
    'name' : 'www-client/microsoft-edge',
    'unaffected' : make_list("ge 113.0.1774.50"),
    'vulnerable' : make_list("lt 113.0.1774.50")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Chromium / Google Chrome / Microsoft Edge');
}
