#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144240);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/19");

  script_cve_id("CVE-2019-10146", "CVE-2019-10179", "CVE-2019-11358");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"EulerOS 2.0 SP5 : pki-core (EulerOS-SA-2020-2560)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the pki-core packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A vulnerability was found in all pki-core 10.x.x
    versions, where the Key Recovery Authority (KRA) Agent
    Service did not properly sanitize recovery request
    search page, enabling a Reflected Cross Site Scripting
    (XSS) vulnerability. An attacker could trick an
    authenticated victim into executing specially crafted
    Javascript code.(CVE-2019-10179)

  - A Reflected Cross Site Scripting flaw was found in all
    pki-core 10.x.x versions module from the pki-core
    server due to the CA Agent Service not properly
    sanitizing the certificate request page. An attacker
    could inject a specially crafted value that will be
    executed on the victim's browser.(CVE-2019-10146)

  - jQuery before 3.4.0, as used in Drupal, Backdrop CMS,
    and other products, mishandles jQuery.extend(true, {},
    ...) because of Object.prototype pollution. If an
    unsanitized source object contained an enumerable
    __proto__ property, it could extend the native
    Object.prototype.(CVE-2019-11358)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2560
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72c9a09f");
  script_set_attribute(attribute:"solution", value:
"Update the affected pki-core packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11358");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pki-tools");
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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["pki-base-10.5.1-14.h3.eulerosv2r7",
        "pki-base-java-10.5.1-14.h3.eulerosv2r7",
        "pki-ca-10.5.1-14.h3.eulerosv2r7",
        "pki-kra-10.5.1-14.h3.eulerosv2r7",
        "pki-server-10.5.1-14.h3.eulerosv2r7",
        "pki-symkey-10.5.1-14.h3.eulerosv2r7",
        "pki-tools-10.5.1-14.h3.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pki-core");
}
