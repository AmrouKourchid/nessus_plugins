#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-96516ce0ac.
#

include('compat.inc');

if (description)
{
  script_id(128484);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/29");

  script_cve_id(
    "CVE-2019-2580",
    "CVE-2019-2581",
    "CVE-2019-2584",
    "CVE-2019-2585",
    "CVE-2019-2587",
    "CVE-2019-2589",
    "CVE-2019-2592",
    "CVE-2019-2593",
    "CVE-2019-2596",
    "CVE-2019-2606",
    "CVE-2019-2607",
    "CVE-2019-2614",
    "CVE-2019-2617",
    "CVE-2019-2620",
    "CVE-2019-2737",
    "CVE-2019-2738",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2752",
    "CVE-2019-2755",
    "CVE-2019-2757",
    "CVE-2019-2758",
    "CVE-2019-2774",
    "CVE-2019-2778",
    "CVE-2019-2780",
    "CVE-2019-2784",
    "CVE-2019-2785",
    "CVE-2019-2789"
  );
  script_xref(name:"FEDORA", value:"2019-96516ce0ac");

  script_name(english:"Fedora 29 : community-mysql (2019-96516ce0ac)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"**MySQL 8.0.17**

This update brings the latest MySQL 8.0.17 which fixes severe security
issues. Now available as both a standard package and a module!

Release notes :

https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-17.html

Mainatiner notes :

  - The MySQL Modules are now built from the same sources as
    the base packages, so the should be identical

  - The package is now being built with number of standard
    Fedora build flags that has not been used before. The
    package should be now more stable and secure.

  - In Modules, the bug #1729133 still exists

  - The MySQL 5.7 and 5.6 Modules may exists, but I'm out of
    capacity to maintain them. Whenever possible upgrade to
    MySQL 8.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-96516ce0ac");
  script_set_attribute(attribute:"solution", value:
"Update the affected community-mysql package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2778");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:community-mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"community-mysql-8.0.17-2.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "community-mysql");
}
