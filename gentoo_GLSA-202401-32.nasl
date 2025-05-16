#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202401-32.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(189845);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/31");

  script_cve_id(
    "CVE-2020-36129",
    "CVE-2020-36130",
    "CVE-2020-36131",
    "CVE-2020-36133",
    "CVE-2020-36134",
    "CVE-2020-36135",
    "CVE-2021-30473",
    "CVE-2021-30474",
    "CVE-2021-30475"
  );

  script_name(english:"GLSA-202401-32 : libaom: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202401-32 (libaom: Multiple Vulnerabilities)

  - AOM v2.0.1 was discovered to contain a stack buffer overflow via the component src/aom_image.c.
    (CVE-2020-36129)

  - AOM v2.0.1 was discovered to contain a NULL pointer dereference via the component av1/av1_dx_iface.c.
    (CVE-2020-36130)

  - AOM v2.0.1 was discovered to contain a stack buffer overflow via the component stats/rate_hist.c.
    (CVE-2020-36131)

  - AOM v2.0.1 was discovered to contain a global buffer overflow via the component
    av1/encoder/partition_search.h. (CVE-2020-36133)

  - AOM v2.0.1 was discovered to contain a segmentation violation via the component
    aom_dsp/x86/obmc_sad_avx2.c. (CVE-2020-36134)

  - AOM v2.0.1 was discovered to contain a NULL pointer dereference via the component rate_hist.c.
    (CVE-2020-36135)

  - aom_image.c in libaom in AOMedia before 2021-04-07 frees memory that is not located on the heap.
    (CVE-2021-30473)

  - aom_dsp/grain_table.c in libaom in AOMedia before 2021-03-30 has a use-after-free. (CVE-2021-30474)

  - aom_dsp/noise_model.c in libaom in AOMedia before 2021-03-24 has a buffer overflow. (CVE-2021-30475)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202401-32");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=793932");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=798126");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=828112");
  script_set_attribute(attribute:"solution", value:
"All libaom users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-libs/libaom-3.2.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30475");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libaom");
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
    'name' : 'media-libs/libaom',
    'unaffected' : make_list("ge 3.2.0"),
    'vulnerable' : make_list("lt 3.2.0")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libaom');
}
