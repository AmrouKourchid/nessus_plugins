#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202405-07.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(194977);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/04");

  script_cve_id(
    "CVE-2021-20308",
    "CVE-2021-23158",
    "CVE-2021-23165",
    "CVE-2021-23180",
    "CVE-2021-23191",
    "CVE-2021-23206",
    "CVE-2021-26252",
    "CVE-2021-26259",
    "CVE-2021-26948",
    "CVE-2021-33235",
    "CVE-2021-33236",
    "CVE-2021-40985",
    "CVE-2021-43579",
    "CVE-2022-0137",
    "CVE-2022-0534",
    "CVE-2022-24191",
    "CVE-2022-27114",
    "CVE-2022-28085",
    "CVE-2022-34033",
    "CVE-2022-34035"
  );

  script_name(english:"GLSA-202405-07 : HTMLDOC: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202405-07 (HTMLDOC: Multiple Vulnerabilities)

  - Integer overflow in the htmldoc 1.9.11 and before may allow attackers to execute arbitrary code and cause
    a denial of service that is similar to CVE-2017-9181. (CVE-2021-20308)

  - A flaw was found in htmldoc in v1.9.12. Double-free in function pspdf_export(),in ps-pdf.cxx may result in
    a write-what-where condition, allowing an attacker to execute arbitrary code and denial of service.
    (CVE-2021-23158)

  - A flaw was found in htmldoc before v1.9.12. Heap buffer overflow in pspdf_prepare_outpages(), in ps-
    pdf.cxx may lead to execute arbitrary code and denial of service. (CVE-2021-23165)

  - A flaw was found in htmldoc in v1.9.12 and before. Null pointer dereference in file_extension(),in file.c
    may lead to execute arbitrary code and denial of service. (CVE-2021-23180)

  - A security issue was found in htmldoc v1.9.12 and before. A NULL pointer dereference in the function
    image_load_jpeg() in image.cxx may result in denial of service. (CVE-2021-23191)

  - A flaw was found in htmldoc in v1.9.12 and prior. A stack buffer overflow in parse_table() in ps-pdf.cxx
    may lead to execute arbitrary code and denial of service. (CVE-2021-23206)

  - A flaw was found in htmldoc in v1.9.12. Heap buffer overflow in pspdf_prepare_page(),in ps-pdf.cxx may
    lead to execute arbitrary code and denial of service. (CVE-2021-26252)

  - A flaw was found in htmldoc in v1.9.12. Heap buffer overflow in render_table_row(),in ps-pdf.cxx may lead
    to arbitrary code execution and denial of service. (CVE-2021-26259)

  - Null pointer dereference in the htmldoc v1.9.11 and before may allow attackers to execute arbitrary code
    and cause a denial of service via a crafted html file. (CVE-2021-26948)

  - Buffer overflow vulnerability in write_node in htmldoc through 1.9.11 allows attackers to cause a denial
    of service via htmldoc/htmldoc/html.cxx:588. (CVE-2021-33235)

  - Buffer Overflow vulnerability in write_header in htmldoc through 1.9.11 allows attackers to casue a denial
    of service via /htmldoc/htmldoc/html.cxx:273. (CVE-2021-33236)

  - A stack-based buffer under-read in htmldoc before 1.9.12, allows attackers to cause a denial of service
    via a crafted BMP image to image_load_bmp. (CVE-2021-40985)

  - A stack-based buffer overflow in image_load_bmp() in HTMLDOC <= 1.9.13 results in remote code execution if
    the victim converts an HTML document linking to a crafted BMP file. (CVE-2021-43579)

  - A heap buffer overflow in image_set_mask function of HTMLDOC before 1.9.15 allows an attacker to write
    outside the buffer boundaries. (CVE-2022-0137)

  - A vulnerability was found in htmldoc version 1.9.15 where the stack out-of-bounds read takes place in
    gif_get_code() and occurs when opening a malicious GIF file, which can result in a crash (segmentation
    fault). (CVE-2022-0534)

  - In HTMLDOC 1.9.14, an infinite loop in the gif_read_lzw function can lead to a pointer arbitrarily
    pointing to heap memory and resulting in a buffer overflow. (CVE-2022-24191)

  - There is a vulnerability in htmldoc 1.9.16. In image_load_jpeg function image.cxx when it calls
    malloc,'img->width' and 'img->height' they are large enough to cause an integer overflow. So, the malloc
    function may return a heap blosmaller than the expected size, and it will cause a buffer overflow/Address
    boundary error in the jpeg_read_scanlines function. (CVE-2022-27114)

  - A flaw was found in htmldoc commit 31f7804. A heap buffer overflow in the function pdf_write_names in ps-
    pdf.cxx may lead to arbitrary code execution and Denial of Service (DoS). (CVE-2022-28085)

  - HTMLDoc v1.9.15 was discovered to contain a heap overflow via (write_header)
    /htmldoc/htmldoc/html.cxx:273. (CVE-2022-34033)

  - HTMLDoc v1.9.12 and below was discovered to contain a heap overflow via e_node
    htmldoc/htmldoc/html.cxx:588. (CVE-2022-34035)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202405-07");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=780489");
  script_set_attribute(attribute:"solution", value:
"All HTMLDOC users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-text/htmldoc-1.9.16");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23165");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:htmldoc");
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
    'name' : 'app-text/htmldoc',
    'unaffected' : make_list("ge 1.9.16"),
    'vulnerable' : make_list("lt 1.9.16")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'HTMLDOC');
}
