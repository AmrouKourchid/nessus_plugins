#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202405-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(194973);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/02");

  script_cve_id(
    "CVE-2021-4219",
    "CVE-2021-20224",
    "CVE-2022-0284",
    "CVE-2022-1115",
    "CVE-2022-2719",
    "CVE-2022-3213",
    "CVE-2022-28463",
    "CVE-2022-32545",
    "CVE-2022-32546",
    "CVE-2022-32547",
    "CVE-2022-44267",
    "CVE-2022-44268",
    "CVE-2023-1906",
    "CVE-2023-2157",
    "CVE-2023-5341",
    "CVE-2023-34151",
    "CVE-2023-34153"
  );
  script_xref(name:"IAVB", value:"2024-B-0077-S");

  script_name(english:"GLSA-202405-02 : ImageMagick: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202405-02 (ImageMagick: Multiple Vulnerabilities)

  - A flaw was found in ImageMagick. The vulnerability occurs due to improper use of open functions and leads
    to a denial of service. This flaw allows an attacker to crash the system. (CVE-2021-4219)

  - An integer overflow issue was discovered in ImageMagick's ExportIndexQuantum() function in
    MagickCore/quantum-export.c. Function calls to GetPixelIndex() could result in values outside the range of
    representable for the 'unsigned char'. When ImageMagick processes a crafted pdf file, this could lead to
    an undefined behaviour or a crash. (CVE-2021-20224)

  - A heap-based-buffer-over-read flaw was found in ImageMagick's GetPixelAlpha() function of 'pixel-
    accessor.h'. This vulnerability is triggered when an attacker passes a specially crafted Tagged Image File
    Format (TIFF) image to convert it into a PICON file format. This issue can potentially lead to a denial of
    service and information disclosure. (CVE-2022-0284)

  - A heap-buffer-overflow flaw was found in ImageMagick's PushShortPixel() function of quantum-private.h
    file. This vulnerability is triggered when an attacker passes a specially crafted TIFF image file to
    ImageMagick for conversion, potentially leading to a denial of service. (CVE-2022-1115)

  - In ImageMagick, a crafted file could trigger an assertion failure when a call to WriteImages was made in
    MagickWand/operation.c, due to a NULL image list. This could potentially cause a denial of service. This
    was fixed in upstream ImageMagick version 7.1.0-30. (CVE-2022-2719)

  - A heap buffer overflow issue was found in ImageMagick. When an application processes a malformed TIFF
    file, it could lead to undefined behavior or a crash causing a denial of service. (CVE-2022-3213)

  - ImageMagick 7.1.0-27 is vulnerable to Buffer Overflow. (CVE-2022-28463)

  - A vulnerability was found in ImageMagick, causing an outside the range of representable values of type
    'unsigned char' at coders/psd.c, when crafted or untrusted input is processed. This leads to a negative
    impact to application availability or other problems related to undefined behavior. (CVE-2022-32545)

  - A vulnerability was found in ImageMagick, causing an outside the range of representable values of type
    'unsigned long' at coders/pcl.c, when crafted or untrusted input is processed. This leads to a negative
    impact to application availability or other problems related to undefined behavior. (CVE-2022-32546)

  - In ImageMagick, there is load of misaligned address for type 'double', which requires 8 byte alignment and
    for type 'float', which requires 4 byte alignment at MagickCore/property.c. Whenever crafted or untrusted
    input is processed by ImageMagick, this causes a negative impact to application availability or other
    problems related to undefined behavior. (CVE-2022-32547)

  - ImageMagick 7.1.0-49 is vulnerable to Denial of Service. When it parses a PNG image (e.g., for resize),
    the convert process could be left waiting for stdin input. (CVE-2022-44267)

  - ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for
    resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary
    has permissions to read it). (CVE-2022-44268)

  - A heap-based buffer overflow issue was discovered in ImageMagick's ImportMultiSpectralQuantum() function
    in MagickCore/quantum-import.c. An attacker could pass specially crafted file to convert, triggering an
    out-of-bounds read error, allowing an application to crash, resulting in a denial of service.
    (CVE-2023-1906)

  - A heap-based buffer overflow vulnerability was found in the ImageMagick package that can lead to the
    application crashing. (CVE-2023-2157)

  - A heap use-after-free flaw was found in coders/bmp.c in ImageMagick. (CVE-2023-5341)

  - A vulnerability was found in ImageMagick. This security flaw ouccers as an undefined behaviors of casting
    double to size_t in svg, mvg and other coders (recurring bugs of CVE-2022-32546). (CVE-2023-34151)

  - A vulnerability was found in ImageMagick. This security flaw causes a shell command injection
    vulnerability via video:vsync or video:pixel-format options in VIDEO encoding/decoding. (CVE-2023-34153)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202405-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835931");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=843833");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=852947");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=871954");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=893526");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=904357");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=908082");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=917594");
  script_set_attribute(attribute:"solution", value:
"All ImageMagick 6.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-gfx/imagemagick-6.9.13.0 =media-gfx/imagemagick-6*
        
All ImageMagick 7.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-gfx/imagemagick-7.1.1.22");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32547");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-34153");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'name' : 'media-gfx/imagemagick',
    'unaffected' : make_list("ge 6.9.13.0", "lt 6.0.0"),
    'vulnerable' : make_list("lt 6.9.12.88")
  },
  {
    'name' : 'media-gfx/imagemagick',
    'unaffected' : make_list("ge 7.1.1.22", "lt 7.0.0"),
    'vulnerable' : make_list("lt 7.1.1.11")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ImageMagick');
}
