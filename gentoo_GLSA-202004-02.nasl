#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202004-02.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(135113);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/20");

  script_cve_id(
    "CVE-2019-2926",
    "CVE-2019-2944",
    "CVE-2019-2984",
    "CVE-2019-3002",
    "CVE-2019-3005",
    "CVE-2019-3017",
    "CVE-2019-3021",
    "CVE-2019-3026",
    "CVE-2019-3028",
    "CVE-2019-3031",
    "CVE-2020-2674",
    "CVE-2020-2678",
    "CVE-2020-2681",
    "CVE-2020-2682",
    "CVE-2020-2689",
    "CVE-2020-2690",
    "CVE-2020-2691",
    "CVE-2020-2692",
    "CVE-2020-2693",
    "CVE-2020-2698",
    "CVE-2020-2702",
    "CVE-2020-2703",
    "CVE-2020-2704",
    "CVE-2020-2705",
    "CVE-2020-2725",
    "CVE-2020-2726",
    "CVE-2020-2727"
  );
  script_xref(name:"GLSA", value:"202004-02");

  script_name(english:"GLSA-202004-02 : VirtualBox: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Gentoo host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202004-02
(VirtualBox: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in VirtualBox. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    An attacker could take control of VirtualBox resulting in the execution
      of arbitrary code with the privileges of the process, a Denial of Service
      condition, or other unspecified impacts.
  
Workaround :

    There is no known workaround at this time.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202004-02");
  script_set_attribute(attribute:"solution", value:
"All VirtualBox 5.2.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-5.2.36'
    All VirtualBox 6.0.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-6.0.16'
    All VirtualBox 6.1.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-6.1.2'
    All VirtualBox binary 5.2.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/virtualbox-bin-5.2.36'
    All VirtualBox binary 6.0.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/virtualbox-bin-6.0.16'
    All VirtualBox binary 6.1.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/virtualbox-bin-6.1.2'");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2682");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3028");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-bin");
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

if (qpkg_check(package:"app-emulation/virtualbox", unaffected:make_list("ge 5.2.36"), vulnerable:make_list("lt 5.2.36"))) flag++;
if (qpkg_check(package:"app-emulation/virtualbox-bin", unaffected:make_list("ge 5.2.36"), vulnerable:make_list("lt 5.2.36"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VirtualBox");
}
