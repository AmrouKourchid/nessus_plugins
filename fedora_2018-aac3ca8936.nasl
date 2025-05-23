#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-aac3ca8936.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110823);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2018-11646",
    "CVE-2018-4190",
    "CVE-2018-4199",
    "CVE-2018-4218",
    "CVE-2018-4222",
    "CVE-2018-4232",
    "CVE-2018-4233",
    "CVE-2018-4246"
  );
  script_xref(name:"FEDORA", value:"2018-aac3ca8936");

  script_name(english:"Fedora 27 : webkitgtk4 (2018-aac3ca8936)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update addresses the following vulnerabilities :

  -
    [CVE-2018-4190](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2018-4190),
    [CVE-2018-4199](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2018-4199),
    [CVE-2018-4218](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2018-4218),
    [CVE-2018-4222](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2018-4222),
    [CVE-2018-4232](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2018-4232),
    [CVE-2018-4233](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2018-4233),
    [CVE-2018-4246](https://cve.mitre.org/cgi-bin/cvename.cg
    i?name=CVE-2018-4246),
    [CVE-2018-11646](https://cve.mitre.org/cgi-bin/cvename.c
    gi?name=CVE-2018-11646).

Additional fixes :

  - Fix installation directory of API documentation.

  - Disable Gigacage if mmap fails to allocate in Linux.

  - Add user agent quirk for paypal website.

  - Properly detect compiler flags, needed libs, and
    fallbacks for usage of 64-bit atomic operations.

  - Fix a network process crash when trying to get cookies
    of about:blank page.

  - Fix UI process crash when closing the window under
    Wayland.

  - Fix several crashes and rendering issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-aac3ca8936");
  script_set_attribute(attribute:"solution", value:
"Update the affected webkitgtk4 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4246");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari Proxy Object Type Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"webkitgtk4-2.20.3-1.fc27")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk4");
}
