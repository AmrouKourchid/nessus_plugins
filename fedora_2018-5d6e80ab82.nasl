#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-5d6e80ab82.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120456);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id("CVE-2018-0497");
  script_xref(name:"FEDORA", value:"2018-5d6e80ab82");

  script_name(english:"Fedora 28 : dislocker / dolphin-emu / mbedtls / nekovm (2018-5d6e80ab82)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"- Update to 2.13.0

  - CVE-2018-0497

Release notes:
https://tls.mbed.org/tech-updates/releases/mbedtls-2.13.0-2.7.6-and-2.
1.15-released

Security Advisory:
https://tls.mbed.org/tech-updates/security-advisories/mbedtls-security
-advisory-2018-02

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-5d6e80ab82");
  # https://tls.mbed.org/tech-updates/security-advisories/mbedtls-security-advisory-2018-02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec6b7b20");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0497");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dislocker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dolphin-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mbedtls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nekovm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"FC28", reference:"dislocker-0.7.1-10.fc28")) flag++;
if (rpm_check(release:"FC28", reference:"dolphin-emu-5.0-25.fc28")) flag++;
if (rpm_check(release:"FC28", reference:"mbedtls-2.13.0-1.fc28")) flag++;
if (rpm_check(release:"FC28", reference:"nekovm-2.2.0-8.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dislocker / dolphin-emu / mbedtls / nekovm");
}
