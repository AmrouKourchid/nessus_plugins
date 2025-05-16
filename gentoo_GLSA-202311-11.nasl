#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202311-11.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(186268);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id(
    "CVE-2022-2294",
    "CVE-2022-3201",
    "CVE-2022-4174",
    "CVE-2022-4175",
    "CVE-2022-4176",
    "CVE-2022-4177",
    "CVE-2022-4178",
    "CVE-2022-4179",
    "CVE-2022-4180",
    "CVE-2022-4181",
    "CVE-2022-4182",
    "CVE-2022-4183",
    "CVE-2022-4184",
    "CVE-2022-4185",
    "CVE-2022-4186",
    "CVE-2022-4187",
    "CVE-2022-4188",
    "CVE-2022-4189",
    "CVE-2022-4190",
    "CVE-2022-4191",
    "CVE-2022-4192",
    "CVE-2022-4193",
    "CVE-2022-4194",
    "CVE-2022-4195",
    "CVE-2022-4436",
    "CVE-2022-4437",
    "CVE-2022-4438",
    "CVE-2022-4439",
    "CVE-2022-4440",
    "CVE-2022-41115",
    "CVE-2022-44688",
    "CVE-2022-44708",
    "CVE-2023-0128",
    "CVE-2023-0129",
    "CVE-2023-0130",
    "CVE-2023-0131",
    "CVE-2023-0132",
    "CVE-2023-0133",
    "CVE-2023-0134",
    "CVE-2023-0135",
    "CVE-2023-0136",
    "CVE-2023-0137",
    "CVE-2023-0138",
    "CVE-2023-0139",
    "CVE-2023-0140",
    "CVE-2023-0141",
    "CVE-2023-2721",
    "CVE-2023-2722",
    "CVE-2023-2723",
    "CVE-2023-2724",
    "CVE-2023-2725",
    "CVE-2023-2726",
    "CVE-2023-2929",
    "CVE-2023-2930",
    "CVE-2023-2931",
    "CVE-2023-2932",
    "CVE-2023-2933",
    "CVE-2023-2934",
    "CVE-2023-2935",
    "CVE-2023-2936",
    "CVE-2023-2937",
    "CVE-2023-2938",
    "CVE-2023-2939",
    "CVE-2023-2940",
    "CVE-2023-2941",
    "CVE-2023-3079",
    "CVE-2023-3214",
    "CVE-2023-3215",
    "CVE-2023-3216",
    "CVE-2023-3217",
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
    "CVE-2023-4078",
    "CVE-2023-4761",
    "CVE-2023-4762",
    "CVE-2023-4763",
    "CVE-2023-4764",
    "CVE-2023-5218",
    "CVE-2023-5473",
    "CVE-2023-5474",
    "CVE-2023-5475",
    "CVE-2023-5476",
    "CVE-2023-5477",
    "CVE-2023-5478",
    "CVE-2023-5479",
    "CVE-2023-5480",
    "CVE-2023-5481",
    "CVE-2023-5482",
    "CVE-2023-5483",
    "CVE-2023-5484",
    "CVE-2023-5485",
    "CVE-2023-5486",
    "CVE-2023-5487",
    "CVE-2023-5849",
    "CVE-2023-5850",
    "CVE-2023-5851",
    "CVE-2023-5852",
    "CVE-2023-5853",
    "CVE-2023-5854",
    "CVE-2023-5855",
    "CVE-2023-5856",
    "CVE-2023-5857",
    "CVE-2023-5858",
    "CVE-2023-5859",
    "CVE-2023-5996",
    "CVE-2023-5997",
    "CVE-2023-6112",
    "CVE-2023-21775",
    "CVE-2023-21796"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"GLSA-202311-11 : QtWebEngine: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202311-11 (QtWebEngine: Multiple Vulnerabilities)

  - Heap buffer overflow in WebRTC in Google Chrome prior to 103.0.5060.114 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2294)

  - Insufficient validation of untrusted input in DevTools in Google Chrome on Chrome OS prior to
    105.0.5195.125 allowed an attacker who convinced a user to install a malicious extension to bypass
    navigation restrictions via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3201)

  - Type confusion in V8 in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4174)

  - Use after free in Camera Capture in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4175)

  - Out of bounds write in Lacros Graphics in Google Chrome on Chrome OS and Lacros prior to 108.0.5359.71
    allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially
    exploit heap corruption via UI interactions. (Chromium security severity: High) (CVE-2022-4176)

  - Use after free in Extensions in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a
    user to install an extension to potentially exploit heap corruption via a crafted Chrome Extension and UI
    interaction. (Chromium security severity: High) (CVE-2022-4177)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2022-4178)

  - Use after free in Audio in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4179)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user to
    install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4180)

  - Use after free in Forms in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4181)

  - Inappropriate implementation in Fenced Frames in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass fenced frame restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4182)

  - Insufficient policy enforcement in Popup Blocker in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4183)

  - Insufficient policy enforcement in Autofill in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass autofill restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4184)

  - Inappropriate implementation in Navigation in Google Chrome on iOS prior to 108.0.5359.71 allowed a remote
    attacker to spoof the contents of the modal dialogue via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4185)

  - Insufficient validation of untrusted input in Downloads in Google Chrome prior to 108.0.5359.71 allowed an
    attacker who convinced a user to install a malicious extension to bypass Downloads restrictions via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2022-4186)

  - Insufficient policy enforcement in DevTools in Google Chrome on Windows prior to 108.0.5359.71 allowed a
    remote attacker to bypass filesystem restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4187)

  - Insufficient validation of untrusted input in CORS in Google Chrome on Android prior to 108.0.5359.71
    allowed a remote attacker to bypass same origin policy via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2022-4188)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 108.0.5359.71 allowed an attacker
    who convinced a user to install a malicious extension to bypass navigation restrictions via a crafted
    Chrome Extension. (Chromium security severity: Medium) (CVE-2022-4189)

  - Insufficient data validation in Directory in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4190)

  - Use after free in Sign-In in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who convinced
    a user to engage in specific UI interaction to potentially exploit heap corruption via profile
    destruction. (Chromium security severity: Medium) (CVE-2022-4191)

  - Use after free in Live Caption in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via UI
    interaction. (Chromium security severity: Medium) (CVE-2022-4192)

  - Insufficient policy enforcement in File System API in Google Chrome prior to 108.0.5359.71 allowed a
    remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4193)

  - Use after free in Accessibility in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4194)

  - Insufficient policy enforcement in Safe Browsing in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass Safe Browsing warnings via a malicious file. (Chromium security severity: Medium)
    (CVE-2022-4195)

  - Use after free in Blink Media in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4436)

  - Use after free in Mojo IPC in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4437)

  - Use after free in Blink Frames in Google Chrome prior to 108.0.5359.124 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2022-4438)

  - Use after free in Aura in Google Chrome on Windows prior to 108.0.5359.124 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via
    specific UI interactions. (Chromium security severity: High) (CVE-2022-4439)

  - Use after free in Profiles in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4440)

  - Microsoft Edge (Chromium-based) Update Elevation of Privilege Vulnerability (CVE-2022-41115)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2022-44688)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability (CVE-2022-44708, CVE-2023-21796)

  - Use after free in Overview Mode in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0128)

  - Heap buffer overflow in Network Service in Google Chrome prior to 109.0.5414.74 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    HTML page and specific interactions. (Chromium security severity: High) (CVE-2023-0129)

  - Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (Chromium security severity: Medium) (CVE-2023-0130)

  - Inappropriate implementation in in iframe Sandbox in Google Chrome prior to 109.0.5414.74 allowed a remote
    attacker to bypass file download restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-0131)

  - Inappropriate implementation in in Permission prompts in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to force acceptance of a permission prompt via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-0132)

  - Inappropriate implementation in in Permission prompts in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to bypass main origin permission delegation via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-0133)

  - Use after free in Cart in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to
    install a malicious extension to potentially exploit heap corruption via database corruption and a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-0134, CVE-2023-0135)

  - Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to execute incorrect security UI via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-0136)

  - Heap buffer overflow in Platform Apps in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed an
    attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via
    a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-0137)

  - Heap buffer overflow in libphonenumber in Google Chrome prior to 109.0.5414.74 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-0138)

  - Insufficient validation of untrusted input in Downloads in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to bypass download restrictions via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0139)

  - Inappropriate implementation in in File System API in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0140)

  - Insufficient policy enforcement in CORS in Google Chrome prior to 109.0.5414.74 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-0141)

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

  - Out of bounds write in Swiftshader in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-2929)

  - Use after free in Extensions in Google Chrome prior to 114.0.5735.90 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2930)

  - Use after free in PDF in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: High) (CVE-2023-2931,
    CVE-2023-2932, CVE-2023-2933)

  - Out of bounds memory access in Mojo in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-2934)

  - Type Confusion in V8 in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-2935,
    CVE-2023-2936)

  - Inappropriate implementation in Picture In Picture in Google Chrome prior to 114.0.5735.90 allowed a
    remote attacker who had compromised the renderer process to spoof the contents of the Omnibox (URL bar)
    via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-2937, CVE-2023-2938)

  - Insufficient data validation in Installer in Google Chrome on Windows prior to 114.0.5735.90 allowed a
    local attacker to perform privilege escalation via crafted symbolic link. (Chromium security severity:
    Medium) (CVE-2023-2939)

  - Inappropriate implementation in Downloads in Google Chrome prior to 114.0.5735.90 allowed an attacker who
    convinced a user to install a malicious extension to bypass file access restrictions via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-2940)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 114.0.5735.90 allowed an attacker
    who convinced a user to install a malicious extension to spoof the contents of the UI via a crafted Chrome
    Extension. (Chromium security severity: Low) (CVE-2023-2941)

  - Type confusion in V8 in Google Chrome prior to 114.0.5735.110 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-3079)

  - Use after free in Autofill payments in Google Chrome prior to 114.0.5735.133 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-3214)

  - Use after free in WebRTC in Google Chrome prior to 114.0.5735.133 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-3215)

  - Type confusion in V8 in Google Chrome prior to 114.0.5735.133 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-3216)

  - Use after free in WebXR in Google Chrome prior to 114.0.5735.133 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-3217)

  - Type Confusion in V8 in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to perform
    arbitrary read/write via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4068,
    CVE-2023-4070)

  - Type Confusion in V8 in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4069)

  - Heap buffer overflow in Visuals in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4071)

  - Out of bounds read and write in WebGL in Google Chrome prior to 115.0.5790.170 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4072)

  - Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 115.0.5790.170 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2023-4073)

  - Use after free in Blink Task Scheduling in Google Chrome prior to 115.0.5790.170 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4074)

  - Use after free in Cast in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4075)

  - Use after free in WebRTC in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted WebRTC session. (Chromium security severity: High) (CVE-2023-4076)

  - Insufficient data validation in Extensions in Google Chrome prior to 115.0.5790.170 allowed an attacker
    who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via
    a crafted Chrome Extension. (Chromium security severity: Medium) (CVE-2023-4077)

  - Inappropriate implementation in Extensions in Google Chrome prior to 115.0.5790.170 allowed an attacker
    who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via
    a crafted Chrome Extension. (Chromium security severity: Medium) (CVE-2023-4078)

  - Out of bounds memory access in FedCM in Google Chrome prior to 116.0.5845.179 allowed a remote attacker
    who had compromised the renderer process to perform an out of bounds memory read via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-4761)

  - Type Confusion in V8 in Google Chrome prior to 116.0.5845.179 allowed a remote attacker to execute
    arbitrary code via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4762)

  - Use after free in Networks in Google Chrome prior to 116.0.5845.179 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4763)

  - Incorrect security UI in BFCache in Google Chrome prior to 116.0.5845.179 allowed a remote attacker to
    spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4764)

  - Use after free in Site Isolation in Google Chrome prior to 118.0.5993.70 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-5218)

  - Use after free in Cast in Google Chrome prior to 118.0.5993.70 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: Low) (CVE-2023-5473)

  - Heap buffer overflow in PDF in Google Chrome prior to 118.0.5993.70 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via a
    crafted PDF file. (Chromium security severity: Medium) (CVE-2023-5474)

  - Inappropriate implementation in DevTools in Google Chrome prior to 118.0.5993.70 allowed an attacker who
    convinced a user to install a malicious extension to bypass discretionary access control via a crafted
    Chrome Extension. (Chromium security severity: Medium) (CVE-2023-5475)

  - Use after free in Blink History in Google Chrome prior to 118.0.5993.70 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5476)

  - Inappropriate implementation in Installer in Google Chrome prior to 118.0.5993.70 allowed a local attacker
    to bypass discretionary access control via a crafted command. (Chromium security severity: Low)
    (CVE-2023-5477)

  - Inappropriate implementation in Autofill in Google Chrome prior to 118.0.5993.70 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-5478)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 118.0.5993.70 allowed an attacker
    who convinced a user to install a malicious extension to bypass an enterprise policy via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-5479)

  - Inappropriate implementation in Payments in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to bypass XSS preventions via a malicious file. (Chromium security severity: High)
    (CVE-2023-5480)

  - Inappropriate implementation in Downloads in Google Chrome prior to 118.0.5993.70 allowed a remote
    attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5481)

  - Insufficient data validation in USB in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5482)

  - Inappropriate implementation in Intents in Google Chrome prior to 118.0.5993.70 allowed a remote attacker
    to bypass content security policy via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5483)

  - Inappropriate implementation in Navigation in Google Chrome prior to 118.0.5993.70 allowed a remote
    attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5484)

  - Inappropriate implementation in Autofill in Google Chrome prior to 118.0.5993.70 allowed a remote attacker
    to bypass autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-5485)

  - Inappropriate implementation in Input in Google Chrome prior to 118.0.5993.70 allowed a remote attacker to
    spoof security UI via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-5486)

  - Inappropriate implementation in Fullscreen in Google Chrome prior to 118.0.5993.70 allowed an attacker who
    convinced a user to install a malicious extension to bypass navigation restrictions via a crafted Chrome
    Extension. (Chromium security severity: Medium) (CVE-2023-5487)

  - Integer overflow in USB in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-5849)

  - Incorrect security UI in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    perform domain spoofing via a crafted domain name. (Chromium security severity: Medium) (CVE-2023-5850)

  - Inappropriate implementation in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5851)

  - Use after free in Printing in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5852)

  - Incorrect security UI in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-5853)

  - Use after free in Profiles in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5854)

  - Use after free in Reading Mode in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5855)

  - Use after free in Side Panel in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-5856)

  - Inappropriate implementation in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to potentially execute arbitrary code via a malicious file. (Chromium security severity: Medium)
    (CVE-2023-5857)

  - Inappropriate implementation in WebApp Provider in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-5858)

  - Incorrect security UI in Picture In Picture in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to perform domain spoofing via a crafted local HTML page. (Chromium security severity: Low)
    (CVE-2023-5859)

  - Use after free in WebAudio in Google Chrome prior to 119.0.6045.123 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5996)

  - Use after free in Garbage Collection in Google Chrome prior to 119.0.6045.159 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5997)

  - Use after free in Navigation in Google Chrome prior to 119.0.6045.159 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-6112)

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability (CVE-2023-21775)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202311-11");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=866332");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=888181");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=903544");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=904290");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=906857");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=909778");
  script_set_attribute(attribute:"solution", value:
"All QtWebEngine users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-qt/qtwebengine-5.15.10_p20230623");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6112");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'dev-qt/qtwebengine',
    'unaffected' : make_list("ge 5.15.10_p20230623"),
    'vulnerable' : make_list("lt 5.15.10_p20230623")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'QtWebEngine');
}
