#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202401-11.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187730);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id(
    "CVE-2018-8013",
    "CVE-2019-17566",
    "CVE-2020-11987",
    "CVE-2022-38398",
    "CVE-2022-38648",
    "CVE-2022-40146",
    "CVE-2022-41704",
    "CVE-2022-42890",
    "CVE-2022-44729",
    "CVE-2022-44730"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"GLSA-202401-11 : Apache Batik: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202401-11 (Apache Batik: Multiple Vulnerabilities)

  - In Apache Batik 1.x before 1.10, when deserializing subclass of `AbstractDocument`, the class takes a
    string from the inputStream as the class name which then use it to call the no-arg constructor of the
    class. Fix was to check the class type before calling newInstance in deserialization. (CVE-2018-8013)

  - Apache Batik is vulnerable to server-side request forgery, caused by improper input validation by the
    xlink:href attributes. By using a specially-crafted argument, an attacker could exploit this
    vulnerability to cause the underlying server to make arbitrary GET requests. (CVE-2019-17566)

  - Apache Batik 1.13 is vulnerable to server-side request forgery, caused by improper input validation by the
    NodePickerPanel. By using a specially-crafted argument, an attacker could exploit this vulnerability to
    cause the underlying server to make arbitrary GET requests. (CVE-2020-11987)

  - Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML Graphics allows an attacker to
    load a url thru the jar protocol. This issue affects Apache XML Graphics Batik 1.14. (CVE-2022-38398)

  - Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML Graphics allows an attacker to
    fetch external resources. This issue affects Apache XML Graphics Batik 1.14. (CVE-2022-38648)

  - Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML Graphics allows an attacker to
    access files using a Jar url. This issue affects Apache XML Graphics Batik 1.14. (CVE-2022-40146)

  - A vulnerability in Batik of Apache XML Graphics allows an attacker to run untrusted Java code from an SVG.
    This issue affects Apache XML Graphics prior to 1.16. It is recommended to update to version 1.16.
    (CVE-2022-41704)

  - A vulnerability in Batik of Apache XML Graphics allows an attacker to run Java code from untrusted SVG via
    JavaScript. This issue affects Apache XML Graphics prior to 1.16. Users are recommended to upgrade to
    version 1.16. (CVE-2022-42890)

  - Server-Side Request Forgery (SSRF) vulnerability in Apache Software Foundation Apache XML Graphics
    Batik.This issue affects Apache XML Graphics Batik: 1.16. On version 1.16, a malicious SVG could trigger
    loading external resources by default, causing resource consumption or in some cases even information
    disclosure. Users are recommended to upgrade to version 1.17 or later. (CVE-2022-44729)

  - Server-Side Request Forgery (SSRF) vulnerability in Apache Software Foundation Apache XML Graphics
    Batik.This issue affects Apache XML Graphics Batik: 1.16. A malicious SVG can probe user profile / data
    and send it directly as parameter to a URL. (CVE-2022-44730)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202401-11");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=724534");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=872689");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918088");
  script_set_attribute(attribute:"solution", value:
"All Apache Batik users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/batik-1.17");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:batik");
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
    'name' : 'dev-java/batik',
    'unaffected' : make_list("ge 1.17"),
    'vulnerable' : make_list("lt 1.17")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Apache Batik');
}
