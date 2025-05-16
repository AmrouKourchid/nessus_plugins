#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202405-32.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(196892);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id(
    "CVE-2024-1546",
    "CVE-2024-1547",
    "CVE-2024-1548",
    "CVE-2024-1549",
    "CVE-2024-1550",
    "CVE-2024-1551",
    "CVE-2024-1552",
    "CVE-2024-1553",
    "CVE-2024-1936",
    "CVE-2024-2609",
    "CVE-2024-3302",
    "CVE-2024-3854",
    "CVE-2024-3857",
    "CVE-2024-3859",
    "CVE-2024-3861",
    "CVE-2024-3864"
  );

  script_name(english:"GLSA-202405-32 : Mozilla Thunderbird: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202405-32 (Mozilla Thunderbird: Multiple
Vulnerabilities)

  - When storing and re-accessing data on a networking channel, the length of buffers may have been confused,
    resulting in an out-of-bounds memory read. This vulnerability affects Firefox < 123, Firefox ESR < 115.8,
    and Thunderbird < 115.8. (CVE-2024-1546)

  - Through a series of API calls and redirects, an attacker-controlled alert dialog could have been displayed
    on another website (with the victim website's URL shown). This vulnerability affects Firefox < 123,
    Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1547)

  - A website could have obscured the fullscreen notification by using a dropdown select input element. This
    could have led to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 123,
    Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1548)

  - If a website set a large custom cursor, portions of the cursor could have overlapped with the permission
    dialog, potentially resulting in user confusion and unexpected granted permissions. This vulnerability
    affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1549)

  - A malicious website could have used a combination of exiting fullscreen mode and `requestPointerLock` to
    cause the user's mouse to be re-positioned unexpectedly, which could have led to user confusion and
    inadvertently granting permissions they did not intend to grant. This vulnerability affects Firefox < 123,
    Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1550)

  - Set-Cookie response headers were being incorrectly honored in multipart HTTP responses. If an attacker
    could control the Content-Type response header, as well as control part of the response body, they could
    inject Set-Cookie response headers that would have been honored by the browser. This vulnerability affects
    Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1551)

  - Incorrect code generation could have led to unexpected numeric conversions and potential undefined
    behavior.*Note:* This issue only affects 32-bit ARM devices. This vulnerability affects Firefox < 123,
    Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1552)

  - Memory safety bugs present in Firefox 122, Firefox ESR 115.7, and Thunderbird 115.7. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and
    Thunderbird < 115.8. (CVE-2024-1553)

  - The encrypted subject of an email message could be incorrectly and permanently assigned to an arbitrary
    other email message in Thunderbird's local cache. Consequently, when replying to the contaminated email
    message, the user might accidentally leak the confidential subject to a third party. While this update
    fixes the bug and avoids future message contamination, it does not automatically repair existing
    contaminations. Users are advised to use the repair folder functionality, which is available from the
    context menu of email folders, which will erase incorrect subject assignments. This vulnerability affects
    Thunderbird < 115.8.1. (CVE-2024-1936)

  - The permission prompt input delay could expire while the window is not in focus. This makes it vulnerable
    to clickjacking by malicious websites. This vulnerability affects Firefox < 124, Firefox ESR < 115.10, and
    Thunderbird < 115.10. (CVE-2024-2609)

  - There was no limit to the number of HTTP/2 CONTINUATION frames that would be processed. A server could
    abuse this to create an Out of Memory condition in the browser. This vulnerability affects Firefox < 125,
    Firefox ESR < 115.10, and Thunderbird < 115.10. (CVE-2024-3302)

  - In some code patterns the JIT incorrectly optimized switch statements and generated code with out-of-
    bounds-reads. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and Thunderbird < 115.10.
    (CVE-2024-3854)

  - The JIT created incorrect code for arguments in certain cases. This led to potential use-after-free
    crashes during garbage collection. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and
    Thunderbird < 115.10. (CVE-2024-3857)

  - On 32-bit versions there were integer-overflows that led to an out-of-bounds-read that potentially could
    be triggered by a malformed OpenType font. This vulnerability affects Firefox < 125, Firefox ESR < 115.10,
    and Thunderbird < 115.10. (CVE-2024-3859)

  - If an AlignedBuffer were assigned to itself, the subsequent self-move could result in an incorrect
    reference count and later use-after-free. This vulnerability affects Firefox < 125, Firefox ESR < 115.10,
    and Thunderbird < 115.10. (CVE-2024-3861)

  - Memory safety bug present in Firefox 124, Firefox ESR 115.9, and Thunderbird 115.9. This bug showed
    evidence of memory corruption and we presume that with enough effort this could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 125, Firefox ESR < 115.10, and Thunderbird < 115.10.
    (CVE-2024-3864)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202405-32");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=925123");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=926533");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=930381");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Thunderbird users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-bin-115.10.0
        
All Mozilla Thunderbird users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-115.10.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1552");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'mail-client/thunderbird',
    'unaffected' : make_list("ge 115.10.0"),
    'vulnerable' : make_list("lt 115.10.0")
  },
  {
    'name' : 'mail-client/thunderbird-bin',
    'unaffected' : make_list("ge 115.10.0"),
    'vulnerable' : make_list("lt 115.10.0")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mozilla Thunderbird');
}
