#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202312-06.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187205);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id(
    "CVE-2020-18771",
    "CVE-2020-18773",
    "CVE-2020-18774",
    "CVE-2020-18899",
    "CVE-2021-29457",
    "CVE-2021-29458",
    "CVE-2021-29463",
    "CVE-2021-29464",
    "CVE-2021-29470",
    "CVE-2021-29473",
    "CVE-2021-29623",
    "CVE-2021-31291",
    "CVE-2021-31292",
    "CVE-2021-32617",
    "CVE-2021-32815",
    "CVE-2021-34334",
    "CVE-2021-34335",
    "CVE-2021-37615",
    "CVE-2021-37616",
    "CVE-2021-37618",
    "CVE-2021-37619",
    "CVE-2021-37620",
    "CVE-2021-37621",
    "CVE-2021-37622",
    "CVE-2021-37623",
    "CVE-2023-44398"
  );

  script_name(english:"GLSA-202312-06 : Exiv2: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202312-06 (Exiv2: Multiple Vulnerabilities)

  - Exiv2 0.27.99.0 has a global buffer over-read in Exiv2::Internal::Nikon1MakerNote::print0x0088 in
    nikonmn_int.cpp which can result in an information leak. (CVE-2020-18771)

  - An invalid memory access in the decode function in iptc.cpp of Exiv2 0.27.99.0 allows attackers to cause a
    denial of service (DOS) via a crafted tif file. (CVE-2020-18773)

  - A float point exception in the printLong function in tags_int.cpp of Exiv2 0.27.99.0 allows attackers to
    cause a denial of service (DOS) via a crafted tif file. (CVE-2020-18774)

  - An uncontrolled memory allocation in DataBufdata(subBox.length-sizeof(box)) function of Exiv2 0.27 allows
    attackers to cause a denial of service (DOS) via a crafted input. (CVE-2020-18899)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A heap buffer overflow was found in Exiv2 versions v0.27.3 and earlier. The heap overflow
    is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could potentially
    exploit the vulnerability to gain code execution, if they can trick the victim into running Exiv2 on a
    crafted image file. Note that this bug is only triggered when _writing_ the metadata, which is a less
    frequently used Exiv2 operation than _reading_ the metadata. For example, to trigger the bug in the Exiv2
    command-line application, you need to add an extra command-line argument such as `insert`. The bug is
    fixed in version v0.27.4. (CVE-2021-29457)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if they can trick
    the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when writing
    the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application, you need to add an extra command-line argument such
    as insert. The bug is fixed in version v0.27.4. (CVE-2021-29458, CVE-2021-29470)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if they can trick
    the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when writing
    the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application, you need to add an extra command-line argument such
    as `insert`. The bug is fixed in version v0.27.4. (CVE-2021-29463)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A heap buffer overflow was found in Exiv2 versions v0.27.3 and earlier. The heap overflow
    is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could potentially
    exploit the vulnerability to gain code execution, if they can trick the victim into running Exiv2 on a
    crafted image file. Note that this bug is only triggered when writing the metadata, which is a less
    frequently used Exiv2 operation than reading the metadata. For example, to trigger the bug in the Exiv2
    command-line application, you need to add an extra command-line argument such as `insert`. The bug is
    fixed in version v0.27.4. (CVE-2021-29464)

  - Exiv2 is a C++ library and a command-line utility to read, write, delete and modify Exif, IPTC, XMP and
    ICC image metadata. An out-of-bounds read was found in Exiv2 versions v0.27.3 and earlier. Exiv2 is a
    command-line utility and C++ library for reading, writing, deleting, and modifying the metadata of image
    files. The out-of-bounds read is triggered when Exiv2 is used to write metadata into a crafted image file.
    An attacker could potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if
    they can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered
    when writing the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For
    example, to trigger the bug in the Exiv2 command-line application, you need to add an extra command-line
    argument such as `insert`. The bug is fixed in version v0.27.4. Please see our security policy for
    information about Exiv2 security. (CVE-2021-29473)

  - Exiv2 is a C++ library and a command-line utility to read, write, delete and modify Exif, IPTC, XMP and
    ICC image metadata. A read of uninitialized memory was found in Exiv2 versions v0.27.3 and earlier. Exiv2
    is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata of
    image files. The read of uninitialized memory is triggered when Exiv2 is used to read the metadata of a
    crafted image file. An attacker could potentially exploit the vulnerability to leak a few bytes of stack
    memory, if they can trick the victim into running Exiv2 on a crafted image file. The bug is fixed in
    version v0.27.4. (CVE-2021-29623)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2021-29457. Reason: This candidate is a
    duplicate of CVE-2021-29457. Notes: All CVE users should reference CVE-2021-29457 instead of this
    candidate. All references and descriptions in this candidate have been removed to prevent accidental usage
    (CVE-2021-31291)

  - An integer overflow in CrwMap::encode0x1810 of Exiv2 0.27.3 allows attackers to trigger a heap-based
    buffer overflow and cause a denial of service (DOS) via crafted metadata. (CVE-2021-31292)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An inefficient algorithm (quadratic complexity) was found in Exiv2 versions v0.27.3 and
    earlier. The inefficient algorithm is triggered when Exiv2 is used to write metadata into a crafted image
    file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.4. Note
    that this bug is only triggered when _writing_ the metadata, which is a less frequently used Exiv2
    operation than _reading_ the metadata. For example, to trigger the bug in the Exiv2 command-line
    application, you need to add an extra command-line argument such as `rm`. (CVE-2021-32617)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. The assertion failure is triggered when Exiv2 is used to modify the metadata of a crafted
    image file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they
    can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when
    modifying the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For
    example, to trigger the bug in the Exiv2 command-line application, you need to add an extra command-line
    argument such as `fi`. ### Patches The bug is fixed in version v0.27.5. ### References Regression test and
    bug fix: #1739 ### For more information Please see our [security
    policy](https://github.com/Exiv2/exiv2/security/policy) for information about Exiv2 security.
    (CVE-2021-32815)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop is triggered when Exiv2 is used to read the metadata of a crafted image
    file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5.
    (CVE-2021-34334)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A floating point exception (FPE) due to an integer divide by zero was found in Exiv2
    versions v0.27.4 and earlier. The FPE is triggered when Exiv2 is used to print the metadata of a crafted
    image file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they
    can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when
    printing the interpreted (translated) data, which is a less frequently used Exiv2 operation that requires
    an extra command line option (`-p t` or `-P t`). The bug is fixed in version v0.27.5. (CVE-2021-34335)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A null pointer dereference was found in Exiv2 versions v0.27.4 and earlier. The null
    pointer dereference is triggered when Exiv2 is used to print the metadata of a crafted image file. An
    attacker could potentially exploit the vulnerability to cause a denial of service, if they can trick the
    victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when printing the
    interpreted (translated) data, which is a less frequently used Exiv2 operation that requires an extra
    command line option (`-p t` or `-P t`). The bug is fixed in version v0.27.5. (CVE-2021-37615,
    CVE-2021-37616)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to print the metadata of a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service, if they can trick the victim into
    running Exiv2 on a crafted image file. Note that this bug is only triggered when printing the image ICC
    profile, which is a less frequently used Exiv2 operation that requires an extra command line option (`-p
    C`). The bug is fixed in version v0.27.5. (CVE-2021-37618)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if they can trick
    the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when writing
    the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application, you need to add an extra command-line argument such
    as insert. The bug is fixed in version v0.27.5. (CVE-2021-37619)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to read the metadata of a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service, if they can trick the victim into
    running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5. (CVE-2021-37620)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The infinite loop is
    triggered when Exiv2 is used to print the metadata of a crafted image file. An attacker could potentially
    exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on
    a crafted image file. Note that this bug is only triggered when printing the image ICC profile, which is a
    less frequently used Exiv2 operation that requires an extra command line option (`-p C`). The bug is fixed
    in version v0.27.5. (CVE-2021-37621)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The infinite loop is
    triggered when Exiv2 is used to modify the metadata of a crafted image file. An attacker could potentially
    exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on
    a crafted image file. Note that this bug is only triggered when deleting the IPTC data, which is a less
    frequently used Exiv2 operation that requires an extra command line option (`-d I rm`). The bug is fixed
    in version v0.27.5. (CVE-2021-37622, CVE-2021-37623)

  - Exiv2 is a C++ library and a command-line utility to read, write, delete and modify Exif, IPTC, XMP and
    ICC image metadata. An out-of-bounds write was found in Exiv2 version v0.28.0. The vulnerable function,
    `BmffImage::brotliUncompress`, is new in v0.28.0, so earlier versions of Exiv2 are _not_ affected. The
    out-of-bounds write is triggered when Exiv2 is used to read the metadata of a crafted image file. An
    attacker could potentially exploit the vulnerability to gain code execution, if they can trick the victim
    into running Exiv2 on a crafted image file. This bug is fixed in version v0.28.1. Users are advised to
    upgrade. There are no known workarounds for this vulnerability. (CVE-2023-44398)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202312-06");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=785646");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=807346");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=917650");
  script_set_attribute(attribute:"solution", value:
"All Exiv2 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-gfx/exiv2-0.28.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29464");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-44398");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:exiv2");
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
    'name' : 'media-gfx/exiv2',
    'unaffected' : make_list("ge 0.28.1"),
    'vulnerable' : make_list("lt 0.28.1")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Exiv2');
}
