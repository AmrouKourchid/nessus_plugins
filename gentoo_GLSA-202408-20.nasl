#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202408-20.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(205344);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/10");

  script_cve_id(
    "CVE-2020-21594",
    "CVE-2020-21595",
    "CVE-2020-21596",
    "CVE-2020-21597",
    "CVE-2020-21598",
    "CVE-2020-21599",
    "CVE-2020-21600",
    "CVE-2020-21601",
    "CVE-2020-21602",
    "CVE-2020-21603",
    "CVE-2020-21604",
    "CVE-2020-21605",
    "CVE-2020-21606",
    "CVE-2021-35452",
    "CVE-2021-36408",
    "CVE-2021-36409",
    "CVE-2021-36410",
    "CVE-2021-36411",
    "CVE-2022-1253",
    "CVE-2022-43235",
    "CVE-2022-43236",
    "CVE-2022-43237",
    "CVE-2022-43238",
    "CVE-2022-43239",
    "CVE-2022-43240",
    "CVE-2022-43241",
    "CVE-2022-43242",
    "CVE-2022-43243",
    "CVE-2022-43244",
    "CVE-2022-43245",
    "CVE-2022-43248",
    "CVE-2022-43249",
    "CVE-2022-43250",
    "CVE-2022-43252",
    "CVE-2022-43253",
    "CVE-2022-47655",
    "CVE-2022-47664",
    "CVE-2022-47665",
    "CVE-2023-24751",
    "CVE-2023-24752",
    "CVE-2023-24754",
    "CVE-2023-24755",
    "CVE-2023-24756",
    "CVE-2023-24757",
    "CVE-2023-24758",
    "CVE-2023-25221"
  );

  script_name(english:"GLSA-202408-20 : libde265: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202408-20 (libde265: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in libde265. Please review the CVE identifiers referenced
    below for details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202408-20");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=813486");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=889876");
  script_set_attribute(attribute:"solution", value:
"All libde265 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-libs/libde265-1.0.11");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1253");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libde265");
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
    'name' : 'media-libs/libde265',
    'unaffected' : make_list("ge 1.0.11"),
    'vulnerable' : make_list("lt 1.0.11")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libde265');
}
