#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202412-06.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(212189);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id(
    "CVE-2024-5693",
    "CVE-2024-5696",
    "CVE-2024-5700",
    "CVE-2024-6601",
    "CVE-2024-6602",
    "CVE-2024-6603",
    "CVE-2024-6604",
    "CVE-2024-7518",
    "CVE-2024-7519",
    "CVE-2024-7520",
    "CVE-2024-7521",
    "CVE-2024-7522",
    "CVE-2024-7523",
    "CVE-2024-7524",
    "CVE-2024-7525",
    "CVE-2024-7526",
    "CVE-2024-7527",
    "CVE-2024-7528",
    "CVE-2024-7529",
    "CVE-2024-7531",
    "CVE-2024-8381",
    "CVE-2024-8382",
    "CVE-2024-8383",
    "CVE-2024-8384",
    "CVE-2024-8385",
    "CVE-2024-8386",
    "CVE-2024-8387",
    "CVE-2024-8389",
    "CVE-2024-8394",
    "CVE-2024-8900",
    "CVE-2024-9391",
    "CVE-2024-9392",
    "CVE-2024-9395",
    "CVE-2024-9396",
    "CVE-2024-9397",
    "CVE-2024-9399",
    "CVE-2024-9400",
    "CVE-2024-9401",
    "CVE-2024-9402",
    "CVE-2024-9403",
    "CVE-2024-10458",
    "CVE-2024-10459",
    "CVE-2024-10460",
    "CVE-2024-10461",
    "CVE-2024-10462",
    "CVE-2024-10463",
    "CVE-2024-10464",
    "CVE-2024-10465",
    "CVE-2024-10466",
    "CVE-2024-10467",
    "CVE-2024-10468"
  );

  script_name(english:"GLSA-202412-06 : Mozilla Thunderbird: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202412-06 (Mozilla Thunderbird: Multiple
Vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Thunderbird. Please review the CVE identifiers
    referenced below for details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202412-06");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=935551");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=936216");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=937468");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=941170");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=941175");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=942470");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Thunderbird users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-bin-128.4.0
        
All Mozilla Thunderbird users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-128.4.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8389");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'mail-client/thunderbird',
    'unaffected' : make_list("ge 128.4.0"),
    'vulnerable' : make_list("lt 128.4.0")
  },
  {
    'name' : 'mail-client/thunderbird-bin',
    'unaffected' : make_list("ge 128.4.0"),
    'vulnerable' : make_list("lt 128.4.0")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mozilla Thunderbird');
}
