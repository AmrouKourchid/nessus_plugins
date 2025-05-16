#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASECS-2024-042.
##

include('compat.inc');

if (description)
{
  script_id(206635);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id(
    "CVE-2023-45289",
    "CVE-2024-24786",
    "CVE-2024-24790",
    "CVE-2024-29018",
    "CVE-2024-36620",
    "CVE-2024-36623",
    "CVE-2024-41110"
  );
  script_xref(name:"IAVB", value:"2024-B-0020-S");
  script_xref(name:"IAVB", value:"2024-B-0071-S");
  script_xref(name:"IAVA", value:"2024-A-0438-S");

  script_name(english:"Amazon Linux 2 : docker (ALASECS-2024-042)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of docker installed on the remote host is prior to 25.0.6-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2ECS-2024-042 advisory.

    2025-01-04: CVE-2024-36620 was added to this advisory.

    2025-01-04: CVE-2024-36623 was added to this advisory.

    When following an HTTP redirect to a domain which is not a subdomain match or exact match of the initial
    domain, an http.Client does not forward sensitive headers such as Authorization or Cookie. For
    example, a redirect from foo.com to www.foo.com will forward the Authorization header, but a redirect to
    bar.com will not. A maliciously crafted HTTP redirect could cause sensitive headers to be unexpectedly
    forwarded. (CVE-2023-45289)

    The protojson.Unmarshal function can enter an infinite loop when unmarshaling certain forms of invalid
    JSON. This condition can occur when unmarshaling into a message which contains a google.protobuf.Any
    value, or when the UnmarshalOptions.DiscardUnknown option is set. (CVE-2024-24786)

    The various Is methods (IsPrivate, IsLoopback, etc) did not work as expected for IPv4-mapped IPv6
    addresses, returning false for addresses which would return true in their traditional IPv4 forms.
    (CVE-2024-24790)

    Moby is an open source container framework that is a key component of Docker Engine, Docker Desktop, and
    other distributions of container tooling or runtimes. Moby's networking implementation allows for many
    networks, each with their own IP address range and gateway, to be defined. This feature is frequently
    referred to as custom networks, as each network can have a different driver, set of parameters and thus
    behaviors. When creating a network, the `--internal` flag is used to designate a network as _internal_.
    The `internal` attribute in a docker-compose.yml file may also be used to mark a network _internal_, and
    other API clients may specify the `internal` parameter as well.

    When containers with networking are created, they are assigned unique network interfaces and IP addresses.
    The host serves as a router for non-internal networks, with a gateway IP that provides SNAT/DNAT to/from
    container IPs.

    Containers on an internal network may communicate between each other, but are precluded from communicating
    with any networks the host has access to (LAN or WAN) as no default route is configured, and firewall
    rules are set up to drop all outgoing traffic. Communication with the gateway IP address (and thus
    appropriately configured host services) is possible, and the host may communicate with any container IP
    directly.

    In addition to configuring the Linux kernel's various networking features to enable container networking,
    `dockerd` directly provides some services to container networks. Principal among these is serving as a
    resolver, enabling service discovery, and resolution of names from an upstream resolver.

    When a DNS request for a name that does not correspond to a container is received, the request is
    forwarded to the configured upstream resolver. This request is made from the container's network
    namespace: the level of access and routing of traffic is the same as if the request was made by the
    container itself.

    As a consequence of this design, containers solely attached to an internal network will be unable to
    resolve names using the upstream resolver, as the container itself is unable to communicate with that
    nameserver. Only the names of containers also attached to the internal network are able to be resolved.

    Many systems run a local forwarding DNS resolver. As the host and any containers have separate loopback
    devices, a consequence of the design described above is that containers are unable to resolve names from
    the host's configured resolver, as they cannot reach these addresses on the host loopback device. To
    bridge this gap, and to allow containers to properly resolve names even when a local forwarding resolver
    is used on a loopback address, `dockerd` detects this scenario and instead forward DNS requests from the
    host namework namespace. The loopback resolver then forwards the requests to its configured upstream
    resolvers, as expected.

    Because `dockerd` forwards DNS requests to the host loopback device, bypassing the container network
    namespace's normal routing semantics entirely, internal networks can unexpectedly forward DNS requests to
    an external nameserver. By registering a domain for which they control the authoritative nameservers, an
    attacker could arrange for a compromised container to exfiltrate data by encoding it in DNS queries that
    will eventually be answered by their nameservers.

    Docker Desktop is not affected, as Docker Desktop always runs an internal resolver on a RFC 1918 address.

    Moby releases 26.0.0, 25.0.4, and 23.0.11 are patched to prevent forwarding any DNS requests from internal
    networks. As a workaround, run containers intended to be solely attached to internal networks with a
    custom upstream address, which will force all upstream DNS queries to be resolved from the container's
    network namespace. (CVE-2024-29018)

    moby v25.0.0 - v26.0.2 is vulnerable to NULL Pointer Dereference via daemon/images/image_history.go.
    (CVE-2024-36620)

    moby v25.0.3 has a Race Condition vulnerability in the streamformatter package which can be used to
    trigger multiple concurrent write operations resulting in data corruption or application crashes.
    (CVE-2024-36623)

    AWS is aware of CVE-2024-41110, an issue affecting the Moby open source project, packaged in Amazon Linux
    as docker. Docker is a component of several open source container management systems.

    This issue does not affect the default configuration of docker. If an authorization plugin is enabled, a
    specially-crafted API request to the docker daemon will be forwarded to the authorization plugin in a way
    that could lead to unintended actions, such as privilege escalation. Enabling an authorization plugin is
    an atypical configuration. The affected API endpoint is not exposed to the network in either the default,
    typical, or recommended configurations. The default EKS and ECS configurations do not expose the API
    endpoint to the network. Enabling a Docker authorization plugin is not supported when using ECS. Finally,
    docker is not installed on EKS AMIs newer than 1.24. Although Docker is installed in EKS 1.24 and earlier,
    EKS does not support authorization plugins.

    Updated docker packages addressing the issue are available for Amazon Linux 2 (docker-20.10.25-1.amzn2.0.5
    and docker-25.0.6-1.amzn2.0.1) and for Amazon Linux 2023 (docker-25.0.6-1amzn2023.0.1). AWS recommends
    that customers using docker upgrade to these or later versions. (CVE-2024-41110)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASECS-2024-042.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-45289.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-24786.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-24790.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-29018.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36620.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-36623.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-41110.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update docker' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24790");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-ecs"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'docker-25.0.6-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-25.0.6-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-debuginfo-25.0.6-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-debuginfo-25.0.6-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-debuginfo");
}
