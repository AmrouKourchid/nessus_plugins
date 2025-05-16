#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202209-05.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164804);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/09");

  script_cve_id(
    "CVE-2021-2161",
    "CVE-2021-2163",
    "CVE-2021-2341",
    "CVE-2021-2369",
    "CVE-2021-2388",
    "CVE-2021-2432",
    "CVE-2021-35550",
    "CVE-2021-35556",
    "CVE-2021-35559",
    "CVE-2021-35561",
    "CVE-2021-35564",
    "CVE-2021-35565",
    "CVE-2021-35567",
    "CVE-2021-35578",
    "CVE-2021-35586",
    "CVE-2021-35588",
    "CVE-2021-35603",
    "CVE-2022-21248",
    "CVE-2022-21271",
    "CVE-2022-21277",
    "CVE-2022-21282",
    "CVE-2022-21283",
    "CVE-2022-21291",
    "CVE-2022-21293",
    "CVE-2022-21294",
    "CVE-2022-21296",
    "CVE-2022-21299",
    "CVE-2022-21305",
    "CVE-2022-21340",
    "CVE-2022-21341",
    "CVE-2022-21349",
    "CVE-2022-21360",
    "CVE-2022-21365",
    "CVE-2022-21366"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"GLSA-202209-05 : OpenJDK: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202209-05 (OpenJDK: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in OpenJDK. Please review the CVE identifiers referenced
    below for details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202209-05");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=784611");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=803605");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831446");
  script_set_attribute(attribute:"solution", value:
"All OpenJDK 8 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-8.322_p06:8
        
All OpenJDK 8 JRE binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-jre-bin-8.322_p06:8
        
All OpenJDK 8 binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-bin-8.322_p06:8
        
All OpenJDK 11 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-11.0.14_p9:11
        
All OpenJDK 11 JRE binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-jre-bin-11.0.14_p9:11
        
All OpenJDK 11 binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-bin-11.0.14_p9:11
        
All OpenJDK 17 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-17.0.2_p8:17
        
All OpenJDK 17 JRE binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-jre-bin-17.0.2_p8:17
        
All OpenJDK 17 binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-bin-17.0.2_p8:17");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35550");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openjdk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openjdk-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'dev-java/openjdk',
    'unaffected' : make_list("ge 11.0.14_p9", "lt 11.0.0"),
    'vulnerable' : make_list("lt 11.0.14_p9")
  },
  {
    'name' : 'dev-java/openjdk',
    'unaffected' : make_list("ge 17.0.2_p8", "lt 17.0.0"),
    'vulnerable' : make_list("lt 17.0.2_p8")
  },
  {
    'name' : 'dev-java/openjdk',
    'unaffected' : make_list("ge 8.322_p06", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.322_p06")
  },
  {
    'name' : 'dev-java/openjdk-bin',
    'unaffected' : make_list("ge 11.0.14_p9", "lt 11.0.0"),
    'vulnerable' : make_list("lt 11.0.14_p9")
  },
  {
    'name' : 'dev-java/openjdk-bin',
    'unaffected' : make_list("ge 17.0.2_p8", "lt 17.0.0"),
    'vulnerable' : make_list("lt 17.0.2_p8")
  },
  {
    'name' : 'dev-java/openjdk-bin',
    'unaffected' : make_list("ge 8.322_p06", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.322_p06")
  },
  {
    'name' : 'dev-java/openjdk-jre-bin',
    'unaffected' : make_list("ge 11.0.14_p9", "lt 11.0.0"),
    'vulnerable' : make_list("lt 11.0.14_p9")
  },
  {
    'name' : 'dev-java/openjdk-jre-bin',
    'unaffected' : make_list("ge 17.0.2_p8", "lt 17.0.0"),
    'vulnerable' : make_list("lt 17.0.2_p8")
  },
  {
    'name' : 'dev-java/openjdk-jre-bin',
    'unaffected' : make_list("ge 8.322_p06", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.322_p06")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'OpenJDK');
}
