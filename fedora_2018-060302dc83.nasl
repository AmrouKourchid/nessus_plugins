#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-060302dc83.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120212);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/09");

  script_cve_id("CVE-2018-19591");
  script_xref(name:"FEDORA", value:"2018-060302dc83");

  script_name(english:"Fedora 28 : glibc (2018-060302dc83)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for the `glibc` package addresses one moderate security
vulnerability and several defects.

  - CVE-2018-19591: A file descriptor leak in
    `if_nametoindex` can lead to a denial of service due to
    resource exhaustion when processing `getaddrinfo` calls
    with crafted host names. Reported by Guido Vranken.
    (RHBZ#1654000)

  - Failure to create the helper thread for
    `getaddrinfo_a`/`libanl` could result in a crash.
    (RHBZ#1646381)

  - On certain Haswell-class Intel CPUs, string function
    feature flags could be set incorrectly, leading to a
    suboptimal choice of string functions. (RHBZ#1641980)

  - Parallel building of locales led to nondeterminism in
    the RPM build process. (RHBZ#1652228)

  - Various minor bug fixes from the upstream 2.27 release
    branch were imported as part of this update
    ([swbz#17630](https://sourceware.org/bugzilla/show_bug.c
    gi?id=17630),
    [swbz#22753](https://sourceware.org/bugzilla/show_bug.cg
    i?id=22753),
    [swbz#23275](https://sourceware.org/bugzilla/show_bug.cg
    i?id=23275),
    [swbz#23562](https://sourceware.org/bugzilla/show_bug.cg
    i?id=23562),
    [swbz#23579](https://sourceware.org/bugzilla/show_bug.cg
    i?id=23579),
    [swbz#23822](https://sourceware.org/bugzilla/show_bug.cg
    i?id=23822)).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-060302dc83");
  script_set_attribute(attribute:"see_also", value:"https://sourceware.org/bugzilla/show_bug.cgi?id=23822");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19591");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");
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
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"glibc-2.27-35.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
