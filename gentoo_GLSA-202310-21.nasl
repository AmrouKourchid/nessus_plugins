#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202310-21.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(184065);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/31");

  script_cve_id(
    "CVE-2022-23096",
    "CVE-2022-23097",
    "CVE-2022-23098",
    "CVE-2022-32292",
    "CVE-2022-32293"
  );

  script_name(english:"GLSA-202310-21 : ConnMan: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202310-21 (ConnMan: Multiple Vulnerabilities)

  - An issue was discovered in the DNS proxy in Connman through 1.40. The TCP server reply implementation
    lacks a check for the presence of sufficient Header Data, leading to an out-of-bounds read.
    (CVE-2022-23096)

  - An issue was discovered in the DNS proxy in Connman through 1.40. forward_dns_reply mishandles a strnlen
    call, leading to an out-of-bounds read. (CVE-2022-23097)

  - An issue was discovered in the DNS proxy in Connman through 1.40. The TCP server reply implementation has
    an infinite loop if no data is received. (CVE-2022-23098)

  - In ConnMan through 1.41, remote attackers able to send HTTP requests to the gweb component are able to
    exploit a heap-based buffer overflow in received_data to execute code. (CVE-2022-32292)

  - In ConnMan through 1.41, a man-in-the-middle attack against a WISPR HTTP query could be used to trigger a
    use-after-free in WISPR handling, leading to crashes or code execution. (CVE-2022-32293)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202310-21");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832028");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=863425");
  script_set_attribute(attribute:"solution", value:
"All ConnMan users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-misc/connman-1.42_pre20220801");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23097");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32292");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:connman");
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
    'name' : 'net-misc/connman',
    'unaffected' : make_list("ge 1.42_pre20220801"),
    'vulnerable' : make_list("lt 1.42_pre20220801")
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
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ConnMan');
}
