#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134482);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/22");

  script_cve_id(
    "CVE-2015-3218",
    "CVE-2015-3255",
    "CVE-2015-4625",
    "CVE-2018-1116",
    "CVE-2018-19788"
  );
  script_bugtraq_id(75267);

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : polkit (EulerOS-SA-2020-1193)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the polkit package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The polkit_backend_action_pool_init function in
    polkitbackend/polkitbackendactionpool.c in PolicyKit
    (aka polkit) before 0.113 might allow local users to
    gain privileges via duplicate action IDs in action
    descriptions.(CVE-2015-3255)

  - A NULL-pointer dereference flaw was discovered in
    polkitd. A malicious, local user could exploit this
    flaw to crash polkitd.(CVE-2015-3218)

  - A flaw was found in PolicyKit (aka polkit) 0.115 that
    allows a user with a uid greater than INT_MAX to
    successfully execute any systemctl
    command.(CVE-2018-19788)

  - It was found that Polkit's CheckAuthorization and
    RegisterAuthenticationAgent D-Bus calls did not
    validate the client provided UID. A specially crafted
    program could use this flaw to submit arbitrary UIDs,
    triggering various denial of service or minor
    disclosures, such as which authentication is cached in
    the victim's session.(CVE-2018-1116)

  - Integer overflow in the authentication_agent_new_cookie
    function in PolicyKit (aka polkit) before 0.113 allows
    local users to gain privileges by creating a large
    number of connections, which triggers the issuance of a
    duplicate cookie value.(CVE-2015-4625)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1193
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51516ee6");
  script_set_attribute(attribute:"solution", value:
"Update the affected polkit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:polkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["polkit-0.112-14.h14"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "polkit");
}
