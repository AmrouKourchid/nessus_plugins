#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202412-07.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(212190);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/09");

  script_cve_id(
    "CVE-2023-22006",
    "CVE-2023-22025",
    "CVE-2023-22036",
    "CVE-2023-22041",
    "CVE-2023-22044",
    "CVE-2023-22045",
    "CVE-2023-22049",
    "CVE-2023-22067",
    "CVE-2023-22081",
    "CVE-2024-20918",
    "CVE-2024-20919",
    "CVE-2024-20921",
    "CVE-2024-20926",
    "CVE-2024-20932",
    "CVE-2024-20945",
    "CVE-2024-20952",
    "CVE-2024-21208",
    "CVE-2024-21210",
    "CVE-2024-21217",
    "CVE-2024-21235"
  );

  script_name(english:"GLSA-202412-07 : OpenJDK: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202412-07 (OpenJDK: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in OpenJDK. Please review the CVE identifiers referenced
    below for details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202412-07");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=912719");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=916211");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=925020");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=941689");
  script_set_attribute(attribute:"solution", value:
"All OpenJDK users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-8.422_p05:8
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-11.0.24_p8:11
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-17.0.12_p7:17
        
All OpenJDK users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-jre-bin-8.442_p05:8
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-jre-bin-11.0.24_p8:11
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-jre-bin-17.0.12_p7:17
        
All OpenJDK users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-bin-8.442_p05:8
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-bin-11.0.24_p8:11
          # emerge --ask --oneshot --verbose >=dev-java/openjdk-bin-17.0.12_p7:17");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openjdk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openjdk-jre-bin");
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
    'name' : 'dev-java/openjdk',
    'unaffected' : make_list("ge 11.0.24_p8", "lt 11.0.0"),
    'vulnerable' : make_list("lt 11.0.24_p8")
  },
  {
    'name' : 'dev-java/openjdk',
    'unaffected' : make_list("ge 17.0.12_p7", "lt 17.0.0"),
    'vulnerable' : make_list("lt 17.0.12_p7")
  },
  {
    'name' : 'dev-java/openjdk',
    'unaffected' : make_list("ge 8.422_p05", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.422_p05")
  },
  {
    'name' : 'dev-java/openjdk-bin',
    'unaffected' : make_list("ge 11.0.24_p8", "lt 11.0.0"),
    'vulnerable' : make_list("lt 11.0.24_p8")
  },
  {
    'name' : 'dev-java/openjdk-bin',
    'unaffected' : make_list("ge 17.0.12_p7", "lt 17.0.0"),
    'vulnerable' : make_list("lt 17.0.12_p7")
  },
  {
    'name' : 'dev-java/openjdk-bin',
    'unaffected' : make_list("ge 8.422_p05", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.422_p05")
  },
  {
    'name' : 'dev-java/openjdk-jre-bin',
    'unaffected' : make_list("ge 11.0.24_p8", "lt 11.0.0"),
    'vulnerable' : make_list("lt 11.0.24_p8")
  },
  {
    'name' : 'dev-java/openjdk-jre-bin',
    'unaffected' : make_list("ge 17.0.12_p7", "lt 17.0.0"),
    'vulnerable' : make_list("lt 17.0.12_p7")
  },
  {
    'name' : 'dev-java/openjdk-jre-bin',
    'unaffected' : make_list("ge 8.422_p05", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.422_p05")
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
