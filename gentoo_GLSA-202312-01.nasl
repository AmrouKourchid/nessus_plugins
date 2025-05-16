#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202312-01.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187052);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/18");

  script_cve_id(
    "CVE-2017-18196",
    "CVE-2018-7186",
    "CVE-2018-7247",
    "CVE-2018-7440",
    "CVE-2018-7441",
    "CVE-2018-7442",
    "CVE-2022-38266"
  );

  script_name(english:"GLSA-202312-01 : Leptonica: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202312-01 (Leptonica: Multiple Vulnerabilities)

  - Leptonica 1.74.4 constructs unintended pathnames (containing duplicated path components) when operating on
    files in /tmp subdirectories, which might allow local users to bypass intended file restrictions by
    leveraging access to a directory located deeper within the /tmp directory tree, as demonstrated by
    /tmp/ANY/PATH/ANY/PATH/input.tif. (CVE-2017-18196)

  - Leptonica before 1.75.3 does not limit the number of characters in a %s format argument to fscanf or
    sscanf, which allows remote attackers to cause a denial of service (stack-based buffer overflow) or
    possibly have unspecified other impact via a long string, as demonstrated by the gplotRead and
    ptaReadStream functions. (CVE-2018-7186)

  - An issue was discovered in pixHtmlViewer in prog/htmlviewer.c in Leptonica before 1.75.3. Unsanitized
    input (rootname) can overflow a buffer, leading potentially to arbitrary code execution or possibly
    unspecified other impact. (CVE-2018-7247)

  - An issue was discovered in Leptonica through 1.75.3. The gplotMakeOutput function allows command injection
    via a $(command) approach in the gplot rootname argument. This issue exists because of an incomplete fix
    for CVE-2018-3836. (CVE-2018-7440)

  - Leptonica through 1.75.3 uses hardcoded /tmp pathnames, which might allow local users to overwrite
    arbitrary files or have unspecified other impact by creating files in advance or winning a race condition,
    as demonstrated by /tmp/junk_split_image.ps in prog/splitimage2pdf.c. (CVE-2018-7441)

  - An issue was discovered in Leptonica through 1.75.3. The gplotMakeOutput function does not block '/'
    characters in the gplot rootname argument, potentially leading to path traversal and arbitrary file
    overwrite. (CVE-2018-7442)

  - An issue in the Leptonica linked library (v1.79.0) allows attackers to cause an arithmetic exception
    leading to a Denial of Service (DoS) via a crafted JPEG file. (CVE-2022-38266)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202312-01");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=649752");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=869416");
  script_set_attribute(attribute:"solution", value:
"All Leptonica users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-libs/leptonica-1.81.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7440");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:leptonica");
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
    'name' : 'media-libs/leptonica',
    'unaffected' : make_list("ge 1.81.0"),
    'vulnerable' : make_list("lt 1.81.0")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Leptonica');
}
