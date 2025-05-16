#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202401-22.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(188051);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/15");

  script_cve_id("CVE-2021-20314", "CVE-2021-33912", "CVE-2021-33913");

  script_name(english:"GLSA-202401-22 : libspf2: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202401-22 (libspf2: Multiple vulnerabilities)

  - Stack buffer overflow in libspf2 versions below 1.2.11 when processing certain SPF macros can lead to
    Denial of service and potentially code execution via malicious crafted SPF explanation messages.
    (CVE-2021-20314)

  - libspf2 before 1.2.11 has a four-byte heap-based buffer overflow that might allow remote attackers to
    execute arbitrary code (via an unauthenticated e-mail message from anywhere on the Internet) with a
    crafted SPF DNS record, because of incorrect sprintf usage in SPF_record_expand_data in spf_expand.c. The
    vulnerable code may be part of the supply chain of a site's e-mail infrastructure (e.g., with additional
    configuration, Exim can use libspf2; the Postfix web site links to unofficial patches for use of libspf2
    with Postfix; older versions of spfquery relied on libspf2) but most often is not. (CVE-2021-33912)

  - libspf2 before 1.2.11 has a heap-based buffer overflow that might allow remote attackers to execute
    arbitrary code (via an unauthenticated e-mail message from anywhere on the Internet) with a crafted SPF
    DNS record, because of SPF_record_expand_data in spf_expand.c. The amount of overflowed data depends on
    the relationship between the length of an entire domain name and the length of its leftmost label. The
    vulnerable code may be part of the supply chain of a site's e-mail infrastructure (e.g., with additional
    configuration, Exim can use libspf2; the Postfix web site links to unofficial patches for use of libspf2
    with Postfix; older versions of spfquery relied on libspf2) but most often is not. (CVE-2021-33913)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202401-22");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=807739");
  script_set_attribute(attribute:"solution", value:
"All libspf2 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-filter/libspf2-1.2.11");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33913");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libspf2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'mail-filter/libspf2',
    'unaffected' : make_list("ge 1.2.11"),
    'vulnerable' : make_list("lt 1.2.11")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libspf2');
}
