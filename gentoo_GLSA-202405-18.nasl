#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202405-18.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(195087);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/07");

  script_cve_id(
    "CVE-2020-25725",
    "CVE-2020-35376",
    "CVE-2021-27548",
    "CVE-2022-24106",
    "CVE-2022-24107",
    "CVE-2022-27135",
    "CVE-2022-38171"
  );

  script_name(english:"GLSA-202405-18 : Xpdf: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202405-18 (Xpdf: Multiple Vulnerabilities)

  - In Xpdf 4.02, SplashOutputDev::endType3Char(GfxState *state) SplashOutputDev.cc:3079 is trying to use the
    freed `t3GlyphStack->cache`, which causes an `heap-use-after-free` problem. The codes of a previous fix
    for nested Type 3 characters wasn't correctly handling the case where a Type 3 char referred to another
    char in the same Type 3 font. (CVE-2020-25725)

  - Xpdf 4.02 allows stack consumption because of an incorrect subroutine reference in a Type 1C font
    charstring, related to the FoFiType1C::getOp() function. (CVE-2020-35376)

  - There is a Null Pointer Dereference vulnerability in the XFAScanner::scanNode() function in XFAScanner.cc
    in xpdf 4.03. (CVE-2021-27548)

  - In Xpdf prior to 4.04, the DCT (JPEG) decoder was incorrectly allowing the 'interleaved' flag to be
    changed after the first scan of the image, leading to an unknown integer-related vulnerability in
    Stream.cc. (CVE-2022-24106)

  - Xpdf prior to 4.04 lacked an integer overflow check in JPXStream.cc. (CVE-2022-24107)

  - xpdf 4.03 has heap buffer overflow in the function readXRefTable located in XRef.cc. An attacker can
    exploit this bug to cause a Denial of Service (Segmentation fault) or other unspecified effects by sending
    a crafted PDF file to the pdftoppm binary. (CVE-2022-27135)

  - Xpdf prior to version 4.04 contains an integer overflow in the JBIG2 decoder
    (JBIG2Stream::readTextRegionSeg() in JBIG2Stream.cc). Processing a specially crafted PDF file or JBIG2
    image could lead to a crash or the execution of arbitrary code. This is similar to the vulnerability
    described by CVE-2021-30860 (Apple CoreGraphics). (CVE-2022-38171)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202405-18");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=755938");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=840873");
  script_set_attribute(attribute:"solution", value:
"All Xpdf users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-text/xpdf-4.04");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35376");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-38171");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xpdf");
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
    'name' : 'app-text/xpdf',
    'unaffected' : make_list("ge 4.04"),
    'vulnerable' : make_list("lt 4.04")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Xpdf');
}
