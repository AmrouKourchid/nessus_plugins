#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201812-02.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(119321);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/18");

  script_cve_id("CVE-2017-12865", "CVE-2017-5716");
  script_xref(name:"GLSA", value:"201812-02");

  script_name(english:"GLSA-201812-02 : ConnMan: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Gentoo host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-201812-02
(ConnMan: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in ConnMan. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker, via a crafted DNS packet, could remotely execute code
      or cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/201812-02");
  script_set_attribute(attribute:"solution", value:
"All ConnMan users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/connman-1.35-r1'");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12865");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:connman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (qpkg_check(package:"net-misc/connman", unaffected:make_list("ge 1.35-r1"), vulnerable:make_list("lt 1.35-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ConnMan");
}
