#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200805-13.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32304);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");
  script_xref(name:"GLSA", value:"200805-13");

  script_name(english:"GLSA-200805-13 : PTeX: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Gentoo host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-200805-13
(PTeX: Multiple vulnerabilities)

    Multiple issues were found in the teTeX 2 codebase that PTeX builds
    upon (GLSA 200709-17, GLSA 200711-26). PTeX also includes vulnerable
    code from the GD library (GLSA 200708-05), from Xpdf (GLSA 200709-12,
    GLSA 200711-22) and from T1Lib (GLSA 200710-12).
  
Impact :

    Remote attackers could possibly execute arbitrary code and local
    attackers could possibly overwrite arbitrary files with the privileges
    of the user running PTeX via multiple vectors, e.g. enticing users to
    open specially crafted files.
  
Workaround :

    There is no known workaround at this time.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200708-05");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200709-12");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200709-17");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200710-12");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200711-22");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200711-26");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200805-13");
  script_set_attribute(attribute:"solution", value:
"All PTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/ptex-3.1.10_p20071203'");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ptex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2008-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"app-text/ptex", unaffected:make_list("ge 3.1.10_p20071203"), vulnerable:make_list("lt 3.1.10_p20071203"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PTeX");
}
