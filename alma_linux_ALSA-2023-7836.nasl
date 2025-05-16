#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:7836.
##

include('compat.inc');

if (description)
{
  script_id(187028);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id(
    "CVE-2021-3468",
    "CVE-2023-38469",
    "CVE-2023-38470",
    "CVE-2023-38471",
    "CVE-2023-38472",
    "CVE-2023-38473"
  );
  script_xref(name:"ALSA", value:"2023:7836");

  script_name(english:"AlmaLinux 8 : avahi (ALSA-2023:7836)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:7836 advisory.

  - A flaw was found in avahi in versions 0.6 up to 0.8. The event used to signal the termination of the
    client connection on the avahi Unix socket is not correctly handled in the client_work function, allowing
    a local attacker to trigger an infinite loop. The highest threat from this vulnerability is to the
    availability of the avahi service, which becomes unresponsive after this flaw is triggered.
    (CVE-2021-3468)

  - A vulnerability was found in Avahi, where a reachable assertion exists in avahi_dns_packet_append_record.
    (CVE-2023-38469)

  - A vulnerability was found in Avahi. A reachable assertion exists in the avahi_escape_label() function.
    (CVE-2023-38470)

  - A vulnerability was found in Avahi. A reachable assertion exists in the dbus_set_host_name function.
    (CVE-2023-38471)

  - A vulnerability was found in Avahi. A reachable assertion exists in the avahi_rdata_parse() function.
    (CVE-2023-38472)

  - A vulnerability was found in Avahi. A reachable assertion exists in the avahi_alternative_host_name()
    function. (CVE-2023-38473)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-7836.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3468");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-38473");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(617, 835);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-compat-howl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-compat-libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-ui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:avahi-ui-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'avahi-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-autoipd-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-compat-howl-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-compat-howl-devel-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-compat-libdns_sd-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-compat-libdns_sd-devel-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-devel-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-glib-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-glib-devel-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-gobject-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-gobject-devel-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-libs-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-tools-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-ui-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-ui-devel-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'avahi-ui-gtk3-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-avahi-0.7-21.el8_9.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'avahi / avahi-autoipd / avahi-compat-howl / avahi-compat-howl-devel / etc');
}
