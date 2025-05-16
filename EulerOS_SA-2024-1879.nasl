#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202406);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2024-29018");

  script_name(english:"EulerOS 2.0 SP10 : docker-engine (EulerOS-SA-2024-1879)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the docker-engine packages installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

    Moby is an open source container framework that is a key component of Docker Engine, Docker Desktop, and
    other distributions of container tooling or runtimes. Moby's networking implementation allows for many
    networks, each with their own IP address range and gateway, to be defined. This feature is frequently
    referred to as custom networks, as each network can have a different driver, set of parameters and thus
    behaviors. When creating a network, the `--internal` flag is used to designate a network as _internal_.
    The `internal` attribute in a docker-compose.yml file may also be used to mark a network _internal_, and
    other API clients may specify the `internal` parameter as well. When containers with networking are
    created, they are assigned unique network interfaces and IP addresses. The host serves as a router for
    non-internal networks, with a gateway IP that provides SNAT/DNAT to/from container IPs. Containers on an
    internal network may communicate between each other, but are precluded from communicating with any
    networks the host has access to (LAN or WAN) as no default route is configured, and firewall rules are set
    up to drop all outgoing traffic. Communication with the gateway IP address (and thus appropriately
    configured host services) is possible, and the host may communicate with any container IP directly. In
    addition to configuring the Linux kernel's various networking features to enable container networking,
    `dockerd` directly provides some services to container networks. Principal among these is serving as a
    resolver, enabling service discovery, and resolution of names from an upstream resolver. When a DNS
    request for a name that does not correspond to a container is received, the request is forwarded to the
    configured upstream resolver. This request is made from the container's network namespace: the level of
    access and routing of traffic is the same as if the request was made by the container itself. As a
    consequence of this design, containers solely attached to an internal network will be unable to resolve
    names using the upstream resolver, as the container itself is unable to communicate with that nameserver.
    Only the names of containers also attached to the internal network are able to be resolved. Many systems
    run a local forwarding DNS resolver. As the host and any containers have separate loopback devices, a
    consequence of the design described above is that containers are unable to resolve names from the host's
    configured resolver, as they cannot reach these addresses on the host loopback device. To bridge this gap,
    and to allow containers to properly resolve names even when a local forwarding resolver is used on a
    loopback address, `dockerd` detects this scenario and instead forward DNS requests from the host namework
    namespace. The loopback resolver then forwards the requests to its configured upstream resolvers, as
    expected. Because `dockerd` forwards DNS requests to the host loopback device, bypassing the container
    network namespace's normal routing semantics entirely, internal networks can unexpectedly forward DNS
    requests to an external nameserver. By registering a domain for which they control the authoritative
    nameservers, an attacker could arrange for a compromised container to exfiltrate data by encoding it in
    DNS queries that will eventually be answered by their nameservers. Docker Desktop is not affected, as
    Docker Desktop always runs an internal resolver on a RFC 1918 address. Moby releases 26.0.0, 25.0.4, and
    23.0.11 are patched to prevent forwarding any DNS requests from internal networks. As a workaround, run
    containers intended to be solely attached to internal networks with a custom upstream address, which will
    force all upstream DNS queries to be resolved from the container's network namespace.(CVE-2024-29018)

Tenable has extracted the preceding description block directly from the EulerOS docker-engine security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1879
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecee9c1f");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker-engine packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:docker-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:docker-engine-selinux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "docker-engine-18.09.0-200.h86.42.30.eulerosv2r10",
  "docker-engine-selinux-18.09.0-200.h86.42.30.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
