#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135744);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2019-19344");

  script_name(english:"EulerOS 2.0 SP8 : samba (EulerOS-SA-2020-1511)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the samba packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerability :

  - There is a use-after-free issue in all samba 4.9.x
    versions before 4.9.18, all samba 4.10.x versions
    before 4.10.12 and all samba 4.11.x versions before
    4.11.5, essentially due to a call to realloc() while
    other local variables still point at the original
    buffer.(CVE-2019-19344)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1511
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82c49964");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["ctdb-4.9.1-2.h21.eulerosv2r8",
        "ctdb-tests-4.9.1-2.h21.eulerosv2r8",
        "libsmbclient-4.9.1-2.h21.eulerosv2r8",
        "libwbclient-4.9.1-2.h21.eulerosv2r8",
        "python2-samba-4.9.1-2.h21.eulerosv2r8",
        "python2-samba-test-4.9.1-2.h21.eulerosv2r8",
        "python3-samba-4.9.1-2.h21.eulerosv2r8",
        "python3-samba-test-4.9.1-2.h21.eulerosv2r8",
        "samba-4.9.1-2.h21.eulerosv2r8",
        "samba-client-4.9.1-2.h21.eulerosv2r8",
        "samba-client-libs-4.9.1-2.h21.eulerosv2r8",
        "samba-common-4.9.1-2.h21.eulerosv2r8",
        "samba-common-libs-4.9.1-2.h21.eulerosv2r8",
        "samba-common-tools-4.9.1-2.h21.eulerosv2r8",
        "samba-dc-libs-4.9.1-2.h21.eulerosv2r8",
        "samba-krb5-printing-4.9.1-2.h21.eulerosv2r8",
        "samba-libs-4.9.1-2.h21.eulerosv2r8",
        "samba-pidl-4.9.1-2.h21.eulerosv2r8",
        "samba-test-4.9.1-2.h21.eulerosv2r8",
        "samba-test-libs-4.9.1-2.h21.eulerosv2r8",
        "samba-winbind-4.9.1-2.h21.eulerosv2r8",
        "samba-winbind-clients-4.9.1-2.h21.eulerosv2r8",
        "samba-winbind-krb5-locator-4.9.1-2.h21.eulerosv2r8",
        "samba-winbind-modules-4.9.1-2.h21.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
