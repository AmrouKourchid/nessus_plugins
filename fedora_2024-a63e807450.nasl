#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-a63e807450
#

include('compat.inc');

if (description)
{
  script_id(194527);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");
  script_xref(name:"FEDORA", value:"2024-a63e807450");

  script_name(english:"Fedora 40 : baresip / libre (2024-a63e807450)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2024-a63e807450 advisory.

    # Baresip v3.10.1 (2024-03-12)

    Security Release (possible Denial of Service): A wrong or manipulated incoming RTP Timestamp can cause the
    baresip process to hang forever, for details see: [#2954](https://github.com/baresip/baresip/issues/2954)

     - aureceiver: fix mtx_unlock on discard


    # Baresip v3.10.0 (2024-03-06)

      - cmake: use default value for `CMAKE_C_EXTENSIONS`
      - cmake: add `/usr/{local,}/include/re` and `/usr/{local,}/lib{64,}` to `FindRE.cmake`
      - test/main: fix `NULL` pointer arg on err
      - ci: add Fedora workflow to avoid e.g. rpath issues
      - mediatrack/start: add `audio_decoder_set`
      - config: support distribution-specific/default CA paths
      - readme: cosmetic changes
      - ci/fedora: fix dependency
      - config: add default CA path for Android
      - transp,tls: add TLS client verification
      - account,message,ua: secure incoming SIP MESSAGEs
      - aufile: avoid race condition in case of fast destruction
      - aufile: join thread if write fails
      - video: add `video_req_keyframe` api
      - call: start streams in `sipsess_estab_handler`
      - webrtc: add av1 codec
      - cmake: fix relative source dir find paths
      - echo: fix `re_snprintf` pointer ARG
      - cmake: Add include PATH so that GST is found also on Debian 11
      - call: improve glare handling
      - call: set estdir in `call_set_media_direction`
      - audio,aur: start audio player after early-video
      - ctrl_dbus: add busctl example to module documentation
      - debian: bump to v3.9.0
      - release v3.10.0


    # libre v3.10.0 (2024-03-06)

      - transp: deref `qent` only if `qentp` is not set
      - sipsess: fix doxygen comments
      - aufile: fix doxygen comment
      - ci/codeql: bump action v3
      - misc: text2pcap helpers (RTP/RTCP capturing)
      - ci/mingw: bump upload/download-artifact and cache versions
      - transp,tls: add TLS client verification
      - fmt/text2pcap: cleanup
      - ci/android: cache openssl build
      - ci/misc: fix double push/pull runs
      - fmt/text2pcap: fix coverity return value warning
      - sipsess/listen: improve glare handling
      - conf: add `conf_get_i32`
      - debian: bump version v3.9.0
      - sip/transp: reset tcp timeout on websocket receive
      - release v3.10.0



Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-a63e807450");
  script_set_attribute(attribute:"solution", value:
"Update the affected baresip and / or libre packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:baresip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libre");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'baresip-3.10.1-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libre-3.10.0-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'baresip / libre');
}
