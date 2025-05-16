#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207200);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id("CVE-2024-32473", "CVE-2024-41110");

  script_name(english:"EulerOS 2.0 SP9 : docker-engine (EulerOS-SA-2024-2385)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the docker-engine packages installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

    Moby is an open source container framework that is a key component of Docker Engine, Docker Desktop, and
    other distributions of container tooling or runtimes. In 26.0.0, IPv6 is not disabled on network
    interfaces, including those belonging to networks where `--ipv6=false`. An container with an `ipvlan` or
    `macvlan` interface will normally be configured to share an external network link with the host machine.
    Because of this direct access, (1) Containers may be able to communicate with other hosts on the local
    network over link-local IPv6 addresses, (2) if router advertisements are being broadcast over the local
    network, containers may get SLAAC-assigned addresses, and (3) the interface  will be a member of IPv6
    multicast groups. This means interfaces in IPv4-only networks present an unexpectedly and unnecessarily
    increased attack surface. The issue is patched in 26.0.2. To completely disable IPv6 in a container, use
    `--sysctl=net.ipv6.conf.all.disable_ipv6=1` in the `docker create` or `docker run` command. Or, in the
    service configuration of a `compose` file.(CVE-2024-32473)

    Moby is an open-source project created by Docker for software containerization. A security vulnerability
    has been detected in certain versions of Docker Engine, which could allow an attacker to bypass
    authorization plugins (AuthZ) under specific circumstances. The base likelihood of this being exploited is
    low.  Using a specially-crafted API request, an Engine API client could make the daemon forward the
    request or response to an authorization plugin without the body. In certain circumstances, the
    authorization plugin may allow a request which it would have otherwise denied if the body had been
    forwarded to it.  A security issue was discovered In 2018, where an attacker could bypass AuthZ plugins
    using a specially crafted API request. This could lead to unauthorized actions, including privilege
    escalation. Although this issue was fixed in Docker Engine v18.09.1 in January 2019, the fix was not
    carried forward to later major versions, resulting in a regression. Anyone who depends on authorization
    plugins that introspect the request and/or response body to make access control decisions is potentially
    impacted.  Docker EE v19.03.x and all versions of Mirantis Container Runtime are not vulnerable.  docker-
    ce v27.1.1 containes patches to fix the vulnerability. Patches have also been merged into the master,
    19.03, 20.0, 23.0, 24.0, 25.0, 26.0, and 26.1 release branches. If one is unable to upgrade immediately,
    avoid using AuthZ plugins and/or restrict access to the Docker API to trusted parties, following the
    principle of least privilege.(CVE-2024-41110)

Tenable has extracted the preceding description block directly from the EulerOS docker-engine security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2385
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc7f78a6");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker-engine packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41110");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:docker-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:docker-engine-selinux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "docker-engine-18.09.0.129-1.h91.43.27.eulerosv2r9",
  "docker-engine-selinux-18.09.0.129-1.h91.43.27.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker-engine");
}
