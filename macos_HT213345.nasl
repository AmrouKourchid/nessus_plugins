#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164291);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/22");

  script_cve_id(
    "CVE-2021-28544",
    "CVE-2022-2294",
    "CVE-2022-24070",
    "CVE-2022-26981",
    "CVE-2022-29046",
    "CVE-2022-29048",
    "CVE-2022-32785",
    "CVE-2022-32786",
    "CVE-2022-32787",
    "CVE-2022-32788",
    "CVE-2022-32789",
    "CVE-2022-32792",
    "CVE-2022-32793",
    "CVE-2022-32796",
    "CVE-2022-32797",
    "CVE-2022-32798",
    "CVE-2022-32799",
    "CVE-2022-32800",
    "CVE-2022-32801",
    "CVE-2022-32802",
    "CVE-2022-32805",
    "CVE-2022-32807",
    "CVE-2022-32810",
    "CVE-2022-32811",
    "CVE-2022-32812",
    "CVE-2022-32813",
    "CVE-2022-32814",
    "CVE-2022-32815",
    "CVE-2022-32816",
    "CVE-2022-32817",
    "CVE-2022-32818",
    "CVE-2022-32819",
    "CVE-2022-32820",
    "CVE-2022-32821",
    "CVE-2022-32823",
    "CVE-2022-32825",
    "CVE-2022-32826",
    "CVE-2022-32828",
    "CVE-2022-32829",
    "CVE-2022-32831",
    "CVE-2022-32832",
    "CVE-2022-32834",
    "CVE-2022-32837",
    "CVE-2022-32838",
    "CVE-2022-32839",
    "CVE-2022-32840",
    "CVE-2022-32841",
    "CVE-2022-32842",
    "CVE-2022-32843",
    "CVE-2022-32845",
    "CVE-2022-32847",
    "CVE-2022-32848",
    "CVE-2022-32849",
    "CVE-2022-32851",
    "CVE-2022-32852",
    "CVE-2022-32853",
    "CVE-2022-32857",
    "CVE-2022-32860",
    "CVE-2022-32861",
    "CVE-2022-32863",
    "CVE-2022-32880",
    "CVE-2022-32885",
    "CVE-2022-32897",
    "CVE-2022-32910",
    "CVE-2022-32933",
    "CVE-2022-32948",
    "CVE-2022-42805",
    "CVE-2022-42858",
    "CVE-2022-46708",
    "CVE-2022-48503",
    "CVE-2022-48578"
  );
  script_xref(name:"APPLE-SA", value:"HT213345");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2022-07-20");
  script_xref(name:"IAVA", value:"2022-A-0295-S");
  script_xref(name:"IAVA", value:"2022-A-0442-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"macOS 12.x < 12.5 Multiple Vulnerabilities (HT213345)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.5. It is, therefore, affected by
multiple vulnerabilities:

  - Apache Subversion SVN authz protected copyfrom paths regression Subversion servers reveal 'copyfrom' paths
    that should be hidden according to configured path-based authorization (authz) rules. When a node has been
    copied from a protected location, users with access to the copy can see the 'copyfrom' path of the
    original. This also reveals the fact that the node was copied. Only the 'copyfrom' path is revealed; not
    its contents. Both httpd and svnserve servers are vulnerable. (CVE-2021-28544)

  - Heap buffer overflow in WebRTC in Google Chrome prior to 103.0.5060.114 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2294)

  - Subversion's mod_dav_svn is vulnerable to memory corruption. While looking up path-based authorization
    rules, mod_dav_svn servers may attempt to use memory which has already been freed. Affected Subversion
    mod_dav_svn servers 1.10.0 through 1.14.1 (inclusive). Servers that do not use mod_dav_svn are not
    affected. (CVE-2022-24070)

  - Liblouis through 3.21.0 has a buffer overflow in compilePassOpcode in compileTranslationTable.c (called,
    indirectly, by tools/lou_checktable.c). (CVE-2022-26981)

  - Jenkins Subversion Plugin 2.15.3 and earlier does not escape the name and description of List Subversion
    tags (and more) parameters on views displaying parameters, resulting in a stored cross-site scripting
    (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-29046)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Subversion Plugin 2.15.3 and earlier allows
    attackers to connect to an attacker-specified URL. (CVE-2022-29048)

  - A null pointer dereference was addressed with improved validation. This issue is fixed in iOS 15.6 and
    iPadOS 15.6, Security Update 2022-005 Catalina, macOS Big Sur 11.6.8, macOS Monterey 12.5. Processing an
    image may lead to a denial-of-service. (CVE-2022-32785)

  - An issue in the handling of environment variables was addressed with improved validation. This issue is
    fixed in Security Update 2022-005 Catalina, macOS Big Sur 11.6.8, macOS Monterey 12.5. An app may be able
    to modify protected parts of the file system. (CVE-2022-32786)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 15.6
    and iPadOS 15.6, macOS Big Sur 11.6.8, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Security Update
    2022-005 Catalina. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2022-32787)

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in watchOS 8.7, tvOS
    15.6, iOS 15.6 and iPadOS 15.6, macOS Monterey 12.5. A remote user may be able to cause kernel code
    execution. (CVE-2022-32788)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.5. An app may
    be able to bypass Privacy preferences. (CVE-2022-32789)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in iOS 15.6
    and iPadOS 15.6, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Safari 15.6. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2022-32792)

  - Multiple out-of-bounds write issues were addressed with improved bounds checking. This issue is fixed in
    macOS Monterey 12.5, watchOS 8.7, tvOS 15.6, iOS 15.6 and iPadOS 15.6. An app may be able to disclose
    kernel memory. (CVE-2022-32793)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in macOS
    Monterey 12.5. An app may be able to execute arbitrary code with kernel privileges. (CVE-2022-32796)

  - This issue was addressed with improved checks. This issue is fixed in Security Update 2022-005 Catalina,
    macOS Big Sur 11.6.8, macOS Monterey 12.5. Processing a maliciously crafted AppleScript binary may result
    in unexpected termination or disclosure of process memory. (CVE-2022-32797)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in macOS
    Monterey 12.5. An app may be able to gain elevated privileges. (CVE-2022-32798)

  - An out-of-bounds read issue was addressed with improved bounds checking. This issue is fixed in Security
    Update 2022-005 Catalina, macOS Monterey 12.5. A user in a privileged network position may be able to leak
    sensitive information. (CVE-2022-32799)

  - This issue was addressed with improved checks. This issue is fixed in Security Update 2022-005 Catalina,
    macOS Big Sur 11.6.8, macOS Monterey 12.5. An app may be able to modify protected parts of the file
    system. (CVE-2022-32800)

  - This issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.5. An app may be
    able to gain root privileges. (CVE-2022-32801)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 15.6 and iPadOS 15.6, tvOS
    15.6, macOS Monterey 12.5. Processing a maliciously crafted file may lead to arbitrary code execution.
    (CVE-2022-32802)

  - The issue was addressed with improved handling of caches. This issue is fixed in Security Update 2022-005
    Catalina, macOS Big Sur 11.6.8, macOS Monterey 12.5. An app may be able to access sensitive user
    information. (CVE-2022-32805)

  - This issue was addressed with improved file handling. This issue is fixed in Security Update 2022-005
    Catalina, macOS Big Sur 11.6.8, macOS Monterey 12.5. An app may be able to overwrite arbitrary files.
    (CVE-2022-32807)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.5, watchOS
    8.7, iOS 15.6 and iPadOS 15.6. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-32810)

  - A memory corruption vulnerability was addressed with improved locking. This issue is fixed in macOS
    Monterey 12.5, macOS Big Sur 11.6.8, Security Update 2022-005 Catalina. An app may be able to execute
    arbitrary code with kernel privileges. (CVE-2022-32811)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.5, macOS
    Big Sur 11.6.8, Security Update 2022-005 Catalina. An app may be able to execute arbitrary code with
    kernel privileges. (CVE-2022-32812)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.5, macOS
    Big Sur 11.6.8, Security Update 2022-005 Catalina, iOS 15.6 and iPadOS 15.6, tvOS 15.6, watchOS 8.7. An
    app with root privileges may be able to execute arbitrary code with kernel privileges. (CVE-2022-32813)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in watchOS 8.7,
    tvOS 15.6, iOS 15.6 and iPadOS 15.6, macOS Monterey 12.5. An app may be able to execute arbitrary code
    with kernel privileges. (CVE-2022-32814)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 15.6 and iPadOS 15.6,
    macOS Big Sur 11.6.8, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Security Update 2022-005 Catalina. An
    app with root privileges may be able to execute arbitrary code with kernel privileges. (CVE-2022-32815,
    CVE-2022-32832)

  - The issue was addressed with improved UI handling. This issue is fixed in watchOS 8.7, tvOS 15.6, iOS 15.6
    and iPadOS 15.6, macOS Monterey 12.5. Visiting a website that frames malicious content may lead to UI
    spoofing. (CVE-2022-32816)

  - An out-of-bounds read issue was addressed with improved bounds checking. This issue is fixed in watchOS
    8.7, tvOS 15.6, iOS 15.6 and iPadOS 15.6, macOS Monterey 12.5. An app may be able to disclose kernel
    memory. (CVE-2022-32817)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.5. An app
    may be able to leak sensitive kernel state. (CVE-2022-32818)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 15.6 and iPadOS
    15.6, macOS Big Sur 11.6.8, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Security Update 2022-005
    Catalina. An app may be able to gain root privileges. (CVE-2022-32819)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in iOS 15.6
    and iPadOS 15.6, macOS Big Sur 11.6.8, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Security Update
    2022-005 Catalina. An app may be able to execute arbitrary code with kernel privileges. (CVE-2022-32820)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in watchOS 8.7, tvOS
    15.6, iOS 15.6 and iPadOS 15.6, macOS Monterey 12.5. An app may be able to execute arbitrary code with
    kernel privileges. (CVE-2022-32821)

  - A memory initialization issue was addressed with improved memory handling. This issue is fixed in iOS 15.6
    and iPadOS 15.6, macOS Big Sur 11.6.8, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Security Update
    2022-005 Catalina. An app may be able to leak sensitive user information. (CVE-2022-32823)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 15.6 and iPadOS 15.6,
    macOS Big Sur 11.6.8, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5. An app may be able to disclose kernel
    memory. (CVE-2022-32825)

  - An authorization issue was addressed with improved state management. This issue is fixed in iOS 15.6 and
    iPadOS 15.6, macOS Big Sur 11.6.8, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Security Update 2022-005
    Catalina. An app may be able to gain root privileges. (CVE-2022-32826)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 15.6 and iPadOS 15.6,
    tvOS 15.6, macOS Monterey 12.5. An app may be able to disclose kernel memory. (CVE-2022-32828)

  - This issue was addressed with improved checks. This issue is fixed in iOS 15.6 and iPadOS 15.6, macOS
    Monterey 12.5. An app may be able to execute arbitrary code with kernel privileges. (CVE-2022-32829)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in Security Update
    2022-005 Catalina, macOS Big Sur 11.6.8, macOS Monterey 12.5. Processing a maliciously crafted AppleScript
    binary may result in unexpected termination or disclosure of process memory. (CVE-2022-32831)

  - An access issue was addressed with improvements to the sandbox. This issue is fixed in macOS Monterey
    12.5, macOS Big Sur 11.6.8, Security Update 2022-005 Catalina. An app may be able to access sensitive user
    information. (CVE-2022-32834)

  - This issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.5, tvOS 15.6, iOS
    15.6 and iPadOS 15.6. An app may be able to cause unexpected system termination or write kernel memory.
    (CVE-2022-32837)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.5,
    macOS Big Sur 11.6.8, Security Update 2022-005 Catalina, iOS 15.6 and iPadOS 15.6. An app may be able to
    read arbitrary files. (CVE-2022-32838)

  - The issue was addressed with improved bounds checks. This issue is fixed in macOS Monterey 12.5, macOS Big
    Sur 11.6.8, Security Update 2022-005 Catalina, iOS 15.6 and iPadOS 15.6, tvOS 15.6, watchOS 8.7. A remote
    user may cause an unexpected app termination or arbitrary code execution. (CVE-2022-32839)

  - This issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.5, watchOS 8.7,
    iOS 15.6 and iPadOS 15.6. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-32840)

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 8.7, tvOS 15.6, iOS
    15.6 and iPadOS 15.6, macOS Monterey 12.5. Processing a maliciously crafted image may result in disclosure
    of process memory. (CVE-2022-32841)

  - An out-of-bounds read issue was addressed with improved input validation. This issue is fixed in Security
    Update 2022-005 Catalina, macOS Monterey 12.5. An app may be able to gain elevated privileges.
    (CVE-2022-32842)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in Security
    Update 2022-005 Catalina, macOS Big Sur 11.6.8, macOS Monterey 12.5. Processing a maliciously crafted
    Postscript file may result in unexpected app termination or disclosure of process memory. (CVE-2022-32843)

  - This issue was addressed with improved checks. This issue is fixed in watchOS 8.7, iOS 15.6 and iPadOS
    15.6, macOS Monterey 12.5. An app may be able to break out of its sandbox. (CVE-2022-32845)

  - This issue was addressed with improved checks. This issue is fixed in iOS 15.6 and iPadOS 15.6, macOS Big
    Sur 11.6.8, watchOS 8.7, tvOS 15.6, macOS Monterey 12.5, Security Update 2022-005 Catalina. A remote user
    may be able to cause unexpected system termination or corrupt kernel memory. (CVE-2022-32847)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.6.8, macOS
    Monterey 12.5. An app may be able to capture a user's screen. (CVE-2022-32848)

  - An information disclosure issue was addressed by removing the vulnerable code. This issue is fixed in iOS
    15.6 and iPadOS 15.6, macOS Big Sur 11.6.8, tvOS 15.6, macOS Monterey 12.5, Security Update 2022-005
    Catalina. An app may be able to access sensitive user information. (CVE-2022-32849)

  - An out-of-bounds read issue was addressed with improved input validation. This issue is fixed in Security
    Update 2022-005 Catalina, macOS Big Sur 11.6.8, macOS Monterey 12.5. Processing a maliciously crafted
    AppleScript binary may result in unexpected termination or disclosure of process memory. (CVE-2022-32851,
    CVE-2022-32853)

  - An out-of-bounds read issue was addressed with improved input validation. This issue is fixed in macOS
    Monterey 12.5. Processing a maliciously crafted AppleScript binary may result in unexpected termination or
    disclosure of process memory. (CVE-2022-32852)

  - This issue was addressed by using HTTPS when sending information over the network. This issue is fixed in
    macOS Monterey 12.5, macOS Big Sur 11.6.8, Security Update 2022-005 Catalina, iOS 15.6 and iPadOS 15.6,
    tvOS 15.6, watchOS 8.7. A user in a privileged network position can track a user's activity.
    (CVE-2022-32857)

  - An out-of-bounds write was addressed with improved input validation. This issue is fixed in iOS 15.6 and
    iPadOS 15.6, macOS Monterey 12.5, macOS Big Sur 11.6.8. An app may be able to execute arbitrary code with
    kernel privileges. (CVE-2022-32860)

  - A logic issue was addressed with improved state management. This issue is fixed in Safari 15.6, macOS
    Monterey 12.5. A user may be tracked through their IP address. (CVE-2022-32861)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in Safari
    15.6, macOS Monterey 12.5. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2022-32863)

  - This issue was addressed by enabling hardened runtime. This issue is fixed in macOS Monterey 12.5. An app
    may be able to access user-sensitive data. (CVE-2022-32880)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 15.6 and
    iPadOS 15.6, macOS Monterey 12.5, Safari 15.6. Processing maliciously crafted web content may lead to
    arbitrary code execution (CVE-2022-32885)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in macOS Monterey
    12.5. Processing a maliciously crafted tiff file may lead to arbitrary code execution. (CVE-2022-32897)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.6.8, macOS
    Monterey 12.5, Security Update 2022-005 Catalina. An archive may be able to bypass Gatekeeper.
    (CVE-2022-32910)

  - An information disclosure issue was addressed by removing the vulnerable code. This issue is fixed in
    macOS Monterey 12.5. A website may be able to track the websites a user visited in Safari private browsing
    mode. (CVE-2022-32933)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in iOS 15.6 and
    iPadOS 15.6, macOS Monterey 12.5. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-32948)

  - An integer overflow was addressed with improved input validation. This issue is fixed in iOS 15.6 and
    iPadOS 15.6, macOS Monterey 12.5. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-42805)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in macOS
    Ventura 13.1. An app may be able to execute arbitrary code with kernel privileges (CVE-2022-42858)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA
    pool that was not assigned to any issues during 2022. Notes: none. (CVE-2022-46708)

  - The issue was addressed with improved bounds checks. This issue is fixed in tvOS 15.6, watchOS 8.7, iOS
    15.6 and iPadOS 15.6, macOS Monterey 12.5, Safari 15.6. Processing web content may lead to arbitrary code
    execution. (CVE-2022-48503)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Monterey
    12.5. Processing an AppleScript may result in unexpected termination or disclosure of process memory.
    (CVE-2022-48578)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213345");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26981");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32845");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '12.5.0', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.5' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
