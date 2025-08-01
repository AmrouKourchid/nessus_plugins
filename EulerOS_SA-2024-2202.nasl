#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205902);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id(
    "CVE-2024-1441",
    "CVE-2024-2494",
    "CVE-2024-2496",
    "CVE-2024-4418"
  );

  script_name(english:"EulerOS Virtualization 2.11.0 : libvirt (EulerOS-SA-2024-2202)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libvirt package installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

    An off-by-one error flaw was found in the udevListInterfacesByStatus() function in libvirt when the number
    of interfaces exceeds the size of the `names` array. This issue can be reproduced by sending specially
    crafted data to the libvirt daemon, allowing an unprivileged client to perform a denial of service attack
    by causing the libvirt daemon to crash.(CVE-2024-1441)

    A NULL pointer dereference flaw was found in the udevConnectListAllInterfaces() function in libvirt. This
    issue can occur when detaching a host interface while at the same time collecting the list of interfaces
    via virConnectListAllInterfaces API. This flaw could be used to perform a denial of service attack by
    causing the libvirt daemon to crash.(CVE-2024-2496)

    While the C API entry points will validate non-negative lengths for various parameters, the RPC server de-
    serialization code will need to allocate memory for arrays before entering the C API. These allocations
    will thus happen before the non-negative length check is performed.  Passing a negative length to the
    g_new0 function will usually result in a crash due to the negative length being treated as a huge positive
    number.  This was found and diagnosed by ALT Linux Team with AFLplusplus.(CVE-2024-2494)

    A race condition leading to a stack use-after-free flaw was found in libvirt. Due to a bad assumption in
    the virNetClientIOEventLoop() method, the data pointer to a stack-allocated virNetClientIOEventData
    structure ended up being used in the virNetClientIOEventFD callback while the data pointer s stack frame
    was concurrently being freed when returning from virNetClientIOEventLoop(). The virtproxyd daemon can be
    used to trigger requests. If libvirt is configured with fine-grained access control, this issue, in
    theory, allows a user to escape their otherwise limited access. This flaw allows a local, unprivileged
    user to access virtproxyd without authenticating. Remote users would need to authenticate before they
    could access it.(CVE-2024-4418)

Tenable has extracted the preceding description block directly from the EulerOS Virtualization libvirt security
advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2202
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b654d05");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvirt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4418");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-2496");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.11.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.11.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "libvirt-6.2.0-2.11.0.5.543"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
