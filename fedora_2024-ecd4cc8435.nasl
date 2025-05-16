#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-ecd4cc8435
#

include('compat.inc');

if (description)
{
  script_id(202743);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2024-3024");
  script_xref(name:"FEDORA", value:"2024-ecd4cc8435");

  script_name(english:"Fedora 40 : tcpreplay (2024-ecd4cc8435)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2024-ecd4cc8435 advisory.

    Announcing v4.5.1

    This release contains contributions from a record number of new contributors. This is greatly appreciated
    since I am a team of one, and do Tcpreplay maintenance in my spare time.

    There are many bug fixes and new features. Most notable features:

     - AF_XDP socket support - if you have a newer Linux kernel, you will be able to transmit at line rates
    without having to install 3rd party kernel modules (e.g. netmap, PF_RING)
     - -w tcpreplay option - this overrides the -i option, and allows you to write to a PCAP file rather than
    an interface
     - --include and --exclude tcpreplay options - allows replay of a list of specific packet numbers to
    replay. This may slow things down, so consider using in combination with -w.
     - --fixhdrlen tcpreplay option - added to control action on packet length changes
     - -W tcpreplay option - suppress warnings when replaying
     - SLL2( Linux cooked capture encapsulation v2)
     - Haiku support

    What's Changed

     - Add support for LINUX_SLL2 by @btriller in #728
     - Feature #727 - Linux SLL v2 by @fklassen in #820
     - Bug #779 - honour overflow for all PPS values by @fklassen in #821
     - AF_XDP socket extension using libxdp api by @plangarbalint in #797
     - Feature #822 - AF_XDP socket extension by @fklassen in #823
     - Nanosec accurate packet processing by @plangarbalint in #796
     - Handle IPv6 fragment extension header by @ChuckCottrill in #832
     - Bug #837 - handle IPv6 fragment extension header by @fklassen in #838
     - Feature #796 - nanosecond packet processing by @fklassen in #836
     - configure.ac: unify search dirs for pcap and add lib32 by @shr-project in #819
     - Feature #839 - add pull request template by @fklassen in #840
     - ipv6 - add check for extension header length by @GabrielGanne in #842
     - Bug #827 PR #842 IPv6 extension header - staging by @fklassen in #859
     - add check for empty cidr by @GabrielGanne in #843
     - Bug #824 and PR #843: check for empty CIDR by @fklassen in #860
     - Add option to turn on/off fix packet header length by @ChuckCottrill in #846
     - Bug #703 #844 PR #846: optionally fix packet header length --fixhdrlen by @fklassen in #861
     - Bug 863: fix nansecond timestamp regression by @fklassen in #865
     - autotools - AC_HELP_STRING is obsolete in 2.70 by @GabrielGanne in #856
     - some Haiku support by @infrastation in #847
     - configure.ac: do not run conftest in case of cross compilation by @ChenQi1989 in #849
     - dlt_jnpr_ether_cleanup: check config before cleanup by @Marsman1996 in #851
     - Fix recursive tcpedit cleanup by @GabrielGanne in #855
     - Bug #813: back out PR #855 by @fklassen in #866
     - Bug #867 - run regfree() on close by @fklassen in #868
     - Bug #869 tcpprep memory leak include exclude by @fklassen in #870
     - Bug #811 - add check for invalid jnpr header length by @fklassen in #872
     - Bug #792 avoid assertion and other fixes by @fklassen in #873
     - Bug #844 tap: ignore TUNSETIFF EBUSY errors by @fklassen in #874
     - Bug #876 - add missing free_umem_and_xsk function by @fklassen in #877
     - Feature #878 - add -w / --suppress-warning option by @fklassen in #879
     - Bug #835 false unsupported dlt warnings on 802.3 (Ethernet I) and LLC by @fklassen in #880
     - Feature #884 include exclude options by @fklassen in #885
     - Feature #853 direct traffic to pcap by @fklassen in #871
     - Feature #853 restore missing -P command by @fklassen in #887
     - Bug #888: check for map == NULL in cidr.c by @fklassen in #889


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-ecd4cc8435");
  script_set_attribute(attribute:"solution", value:
"Update the affected tcpreplay package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3024");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tcpreplay");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'tcpreplay-4.5.1-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tcpreplay');
}
