#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202005-09.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(136639);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id("CVE-2020-8492");
  script_xref(name:"GLSA", value:"202005-09");

  script_name(english:"GLSA-202005-09 : Python: Denial of service");

  script_set_attribute(attribute:"synopsis", value:
"The remote Gentoo host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202005-09
(Python: Denial of service)

    An issue was discovered in urllib.request.AbstractBasicAuthHandler which
      allowed a remote attacker to send malicious data causing extensive
      regular expression backtracking.
  
Impact :

    An attacker could cause a possible Denial of Service condition.
  
Workaround :

    There is no known workaround at this time.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202005-09");
  script_set_attribute(attribute:"solution", value:
"All Python 2.7 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/python-2.7.18-r2:2.7'
    All Python 3.6 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/python-3.6.10-r2:3.6'
    All Python 3.7 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/python-3.7.7-r2:3.7'
    All Python 3.8 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/python-3.8.2-r2:3.8'");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (qpkg_check(package:"dev-lang/python", unaffected:make_list("ge 2.7.18-r2", "ge 3.6.10-r2", "ge 3.7.7-r2", "ge 3.8.2-r2"), vulnerable:make_list("lt 2.7.18-r2", "lt 3.6.10-r2", "lt 3.7.7-r2", "lt 3.8.2-r2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Python");
}
