#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200801-19.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(30136);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");
  script_xref(name:"GLSA", value:"200801-19");

  script_name(english:"GLSA-200801-19 : GOffice: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Gentoo host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-200801-19
(GOffice: Multiple vulnerabilities)

    GOffice includes a copy of PCRE which is vulnerable to multiple buffer
    overflows and memory corruptions vulnerabilities (GLSA 200711-30).
  
Impact :

    An attacker could entice a user to open specially crafted documents
    with GOffice, which could possibly lead to the execution of arbitrary
    code, a Denial of Service or the disclosure of sensitive information.
  
Workaround :

    There is no known workaround at this time.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200711-30");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200801-19");
  script_set_attribute(attribute:"solution", value:
"All GOffice 0.4.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/goffice-0.4.3'
    All GOffice 0.6.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/goffice-0.6.1'");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:goffice");
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

if (qpkg_check(package:"x11-libs/goffice", unaffected:make_list("ge 0.6.1", "rge 0.4.3"), vulnerable:make_list("lt 0.6.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GOffice");
}
