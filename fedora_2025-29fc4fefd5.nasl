#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2025-29fc4fefd5
#

include('compat.inc');

if (description)
{
  script_id(214990);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2025-24356");
  script_xref(name:"FEDORA", value:"2025-29fc4fefd5");

  script_name(english:"Fedora 40 : fastd (2025-29fc4fefd5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2025-29fc4fefd5 advisory.


    This release contains a number of small improvements and bugfixes, including mitigations for the LOW
    severity vulnerability `CVE-2025-24356`.

    ## Bugfixes

    -   Add mitigations for fast-reconnect amplification attacks

        When receiving a data packet from an unknown IP address/port combination, fastd will assume that one
    of its connected peers has moved to a new address (for example due to internet lines with dynamic IP, or
    roaming between WWAN and a local internet connection) and initiate a reconnect by sending a handshake
    packet. This fast reconnect avoids having to wait for a session timeout (up to ~90s) until a new
    connection is established.

        Even a 1-byte UDP packet just containing the fastd packet type header can trigger a much larger
    handshake packet (~150 bytes of UDP payload). With fastd v22, this number is doubled, because two
    handshakes are sent (one in a pre-v22-compatible format and one in a new L2TP-style format). Including
    IPv4 and UDP headers, the resulting amplification factor is roughly 12-13.

        By sending data packets with a spoofed source address to fastd instances reachable on the internet,
    this amplification of UDP traffic might be used to facilitate a Distributed Denial of Service attack.

        fastd has always implemented rate limiting for handshakes to unknown IP addresses and ports to 1
    handshake per 15s to avoid this kind of attack, however the rate is limited per-port and not per-address,
    thus still allowing handshakes to be sent to all 65535 UDP ports of the same IP address unlimited.

        The issue has been mitigated in fastd v23 by a number of changes:

        -   Rate-limiting has been changed changed to be applied per-address instead of per-port

        -   Only one handshake instead of two handshakes is sent for fast-reconnect (by determining from the
    format of the data packet whether a pre-v22 or L2TP-style handshake should be used)

        -   Require at least a full method header instead of just a single byte for a data packet to be
    considered valid. This does not have an effect on instances that enable the `null` method (regardless of
    `null` being actually in use), as a single-byte UDP packet is a valid `null` keepalive, but for all other
    methods the amplification factor is slightly reduced.


        Only fastd instances that allow connections from arbitrary IP addresses are vulnerable. Instances in a
    client role that configure their peers using the `remote` config option (which includes the common
    deployment as part of the [Gluon](https://github.com/freifunk-gluon/gluon) wireless mesh firmware) will
    not respond to unexpected data packets with a handshake and are therefore unaffected.

        `CVE-2025-24356` has been assigned to this issue. The severity of this vulnerability is considered
    LOW.

        A GitHub security advisory can be found under [GHSA-pggg-
    vpfv-4rcv](https://github.com/neocturne/fastd/security/advisories/GHSA-pggg-vpfv-4rcv).

    -   Fix config loading to fail on `offload l2tp no;` when L2TP offloading is unsupported by the fastd
    build or the kernel

    -   Fix assembly Salsa20(/12) implementations accidentally generating the Linux- specific `.note.GNU-
    stack` ELF section on non-Linux systems

        This is unlikely to have caused any issues, as other systems should just ignore the unknown section.

    -   Status socket: - Fix interface name information with L2TP offloading - Add per-peer MTU information

    -   Documentation: - Fix incorrect persist interface examples - Improve explanation of `float`
    option

    -   Build: - Fix build on macOS (again) - Fix build with Meson 0.49 (the minimum version marked as
    supported by fastd)


    ## Other changes

    -   Add support for Indirect Branch Tracking and Shadow Stacks on x86

        The assembly Salsa20(/12) implementations have been marked compatible with IBT and SHSTK, which are
    part of Intel CET (Control-flow Enforcement Technology) and can be enabled using the `-fcf-protection` GCC
    option.

    -   The file `COPYRIGHT` has been renamed to `LICENSE`

    -   The vendored version of libmnl that is used with `libmnl_builtin=true` has been updated to 1.0.5



Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-29fc4fefd5");
  script_set_attribute(attribute:"solution", value:
"Update the affected fastd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24356");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fastd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'fastd-23-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fastd');
}
