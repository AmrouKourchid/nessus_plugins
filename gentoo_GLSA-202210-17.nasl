#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-17.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166730);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2021-3496",
    "CVE-2021-28275",
    "CVE-2021-28276",
    "CVE-2021-28277",
    "CVE-2021-28278"
  );

  script_name(english:"GLSA-202210-17 : JHead: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-17 (JHead: Multiple Vulnerabilities)

  - A Denial of Service vulnerability exists in jhead 3.04 and 3.05 due to a wild address read in the Get16u
    function in exif.c in will cause segmentation fault via a crafted_file. (CVE-2021-28275)

  - A Denial of Service vulnerability exists in jhead 3.04 and 3.05 via a wild address read in the
    ProcessCanonMakerNoteDir function in makernote.c. (CVE-2021-28276)

  - A Heap-based Buffer Overflow vulnerability exists in jhead 3.04 and 3.05 is affected by: Buffer Overflow
    via the RemoveUnknownSections function in jpgfile.c. (CVE-2021-28277)

  - A Heap-based Buffer Overflow vulnerability exists in jhead 3.04 and 3.05 via the RemoveSectionType
    function in jpgfile.c. (CVE-2021-28278)

  - A heap-based buffer overflow was found in jhead in version 3.06 in Get16u() in exif.c when processing a
    crafted file. (CVE-2021-3496)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-17");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=730746");
  script_set_attribute(attribute:"solution", value:
"All JHead users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-gfx/jhead-3.06.0.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3496");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:jhead");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'media-gfx/jhead',
    'unaffected' : make_list("ge 3.06.0.1", "lt 3.0.0"),
    'vulnerable' : make_list("lt 3.06.0.1")
  }
];

foreach package( packages ) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'JHead');
}
