#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202312-03.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187118);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/20");

  script_cve_id(
    "CVE-2023-32205",
    "CVE-2023-32206",
    "CVE-2023-32207",
    "CVE-2023-32211",
    "CVE-2023-32212",
    "CVE-2023-32213",
    "CVE-2023-32214",
    "CVE-2023-32215",
    "CVE-2023-34414",
    "CVE-2023-34416"
  );

  script_name(english:"GLSA-202312-03 : Mozilla Thunderbird: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202312-03 (Mozilla Thunderbird: Multiple
Vulnerabilities)

  - In multiple cases browser prompts could have been obscured by popups controlled by content. These could
    have led to potential user confusion and spoofing attacks. This vulnerability affects Firefox < 113,
    Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32205)

  - An out-of-bound read could have led to a crash in the RLBox Expat driver. This vulnerability affects
    Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32206)

  - A missing delay in popup notifications could have made it possible for an attacker to trick a user into
    granting permissions. This vulnerability affects Firefox < 113, Firefox ESR < 102.11, and Thunderbird <
    102.11. (CVE-2023-32207)

  - A type checking bug would have led to invalid code being compiled. This vulnerability affects Firefox <
    113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32211)

  - An attacker could have positioned a <code>datalist</code> element to obscure the address bar. This
    vulnerability affects Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32212)

  - When reading a file, an uninitialized value could have been used as read limit. This vulnerability affects
    Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32213)

  - Protocol handlers `ms-cxh` and `ms-cxh-full` could have been leveraged to trigger a denial of service.
    *Note: This attack only affects Windows. Other operating systems are not affected.* This vulnerability
    affects Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11. (CVE-2023-32214)

  - Memory safety bugs present in Firefox 112 and Firefox ESR 102.10. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 113, Firefox ESR < 102.11, and Thunderbird < 102.11.
    (CVE-2023-32215)

  - The error page for sites with invalid TLS certificates was missing the activation-delay Firefox uses to
    protect prompts and permission dialogs from attacks that exploit human response time delays. If a
    malicious page elicited user clicks in precise locations immediately before navigating to a site with a
    certificate error and made the renderer extremely busy at the same time, it could create a gap between
    when the error page was loaded and when the display actually refreshed. With the right timing the elicited
    clicks could land in that gap and activate the button that overrides the certificate error for that site.
    This vulnerability affects Firefox ESR < 102.12, Firefox < 114, and Thunderbird < 102.12. (CVE-2023-34414)

  - Memory safety bugs present in Firefox 113, Firefox ESR 102.11, and Thunderbird 102.12. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 102.12, Firefox < 114, and
    Thunderbird < 102.12. (CVE-2023-34416)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202312-03");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=908246");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Thunderbird users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-bin-102.12
        
All Mozilla Thunderbird users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-102.12");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34416");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
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
    'name' : 'mail-client/thunderbird',
    'unaffected' : make_list("ge 102.12"),
    'vulnerable' : make_list("lt 102.12")
  },
  {
    'name' : 'mail-client/thunderbird-bin',
    'unaffected' : make_list("ge 102.12"),
    'vulnerable' : make_list("lt 102.12")
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
