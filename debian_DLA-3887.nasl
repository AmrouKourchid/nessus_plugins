#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3887. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(207275);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/15");

  script_cve_id(
    "CVE-2021-32686",
    "CVE-2021-37706",
    "CVE-2021-43299",
    "CVE-2021-43300",
    "CVE-2021-43301",
    "CVE-2021-43302",
    "CVE-2021-43303",
    "CVE-2021-43804",
    "CVE-2021-43845",
    "CVE-2022-21722",
    "CVE-2022-21723",
    "CVE-2022-23537",
    "CVE-2022-23547",
    "CVE-2022-23608",
    "CVE-2022-24754",
    "CVE-2022-24763",
    "CVE-2022-24764",
    "CVE-2022-24793",
    "CVE-2022-31031",
    "CVE-2022-39244",
    "CVE-2023-27585"
  );

  script_name(english:"Debian dla-3887 : jami - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3887 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3887-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                  Roberto C. Snchez
    September 14, 2024                            https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : ring
    Version        : 20210112.2.b757bac~ds1-1+deb11u1
    CVE ID         : CVE-2021-32686 CVE-2021-37706 CVE-2021-43299 CVE-2021-43300
                     CVE-2021-43301 CVE-2021-43302 CVE-2021-43303 CVE-2021-43804
                     CVE-2021-43845 CVE-2022-21722 CVE-2022-21723 CVE-2022-23537
                     CVE-2022-23547 CVE-2022-23608 CVE-2022-24754 CVE-2022-24763
                     CVE-2022-24764 CVE-2022-24793 CVE-2022-31031 CVE-2022-39244
                     CVE-2023-27585

    Multiple vulnerabilities were found to affect ring, a secure and
    distributed voice, video, and chat platform.

    CVE-2021-32686

        The embedded copy of pjproject is affected by this CVE.
        A race condition between callback and destroy, due to the accepted socket
        having no group lock. Additionally, the SSL socket parent/listener may get
        destroyed during handshake. Both issues were reported to happen
        intermittently in heavy load TLS connections. They cause a crash, resulting
        in a denial of service.

    CVE-2021-37706

        The embedded copy of pjproject is affected by this CVE.
        If the incoming STUN message contains an ERROR-CODE attribute, the header
        length is not checked before performing a subtraction operation, potentially
        resulting in an integer underflow scenario. This issue affects all users
        that use STUN. A malicious actor located within the victim's network may
        forge and send a specially crafted UDP (STUN) message that could remotely
        execute arbitrary code on the victims machine.

    CVE-2021-43299

        The embedded copy of pjproject is affected by these CVEs.
        An attacker-controlled 'filename' argument may cause a buffer overflow since
        it is copied to a fixed-size stack buffer without any size validation.

    CVE-2021-43300

        The embedded copy of pjproject is affected by these CVEs.
        An attacker-controlled 'filename' argument may cause a buffer overflow since
        it is copied to a fixed-size stack buffer without any size validation.

    CVE-2021-43301

        The embedded copy of pjproject is affected by these CVEs.
        An attacker-controlled 'filename' argument may cause a buffer overflow since
        it is copied to a fixed-size stack buffer without any size validation.

    CVE-2021-43302

        The embedded copy of pjproject is affected by these CVEs.
        An attacker-controlled 'filename' argument may cause a buffer overflow since
        it is copied to a fixed-size stack buffer without any size validation.

    CVE-2021-43303

        The embedded copy of pjproject is affected by these CVEs.
        An attacker-controlled 'filename' argument may cause a buffer overflow since
        it is copied to a fixed-size stack buffer without any size validation.

    CVE-2021-43804

        The embedded copy of pjproject is affected by this CVE.
        In affected versions if the incoming RTCP BYE message contains a reason's
        length, this declared length is not checked against the actual received
        packet size, potentially resulting in an out-of-bound read access.

    CVE-2021-43845

        The embedded copy of pjproject is affected by this CVE.
        If incoming RTCP XR message contain block, the data field is not checked
        against the received packet size, potentially resulting in an out-of-bound
        read access.

    CVE-2022-21722

        The embedded copy of pjproject is affected by this CVE.
        There are various cases where it is possible that certain incoming RTP/RTCP
        packets can potentially cause out-of-bound read access.

    CVE-2022-21723

        The embedded copy of pjproject is affected by this CVE.
        Parsing an incoming SIP message that contains a malformed multipart can
        potentially cause out-of-bound read access.

    CVE-2022-23537

        The embedded copy of pjproject is affected by this CVE.
        Buffer overread is possible when parsing a specially crafted STUN message
        with unknown attribute.

    CVE-2022-23547

        The embedded copy of pjproject is affected by this CVE.
        Possible buffer overread when parsing a certain STUN message.

    CVE-2022-23608

        The embedded copy of pjproject is affected by this CVE.
        When in a dialog set (or forking) scenario, a hash key shared by multiple
        UAC dialogs can potentially be prematurely freed when one of the dialogs is
        destroyed . The issue may cause a dialog set to be registered in the hash
        table multiple times (with different hash keys) leading to undefined
        behavior such as dialog list collision which eventually leading to endless
        loop.

    CVE-2022-24754

        The embedded copy of pjproject is affected by this CVE.
        There is a stack-buffer overflow vulnerability which only impacts PJSIP
        users who accept hashed digest credentials (credentials with data_type
        `PJSIP_CRED_DATA_DIGEST`).

    CVE-2022-24763

        The embedded copy of pjproject is affected by this CVE.
        A denial-of-service vulnerability affects PJSIP users that consume PJSIP's
        XML parsing in their apps.

    CVE-2022-24764

        The embedded copy of pjproject is affected by this CVE.
        A stack buffer overflow vulnerability affects PJSUA2 users or users that
        call the API `pjmedia_sdp_print(), pjmedia_sdp_media_print()`.

    CVE-2022-24793

        The embedded copy of pjproject is affected by this CVE.
        A buffer overflow vulnerability in affects applications that use PJSIP DNS
        resolution.

    CVE-2022-31031

        The embedded copy of pjproject is affected by this CVE.
        A stack buffer overflow vulnerability affects PJSIP users that use STUN in
        their applications, either by: setting a STUN server in their account/media
        config in PJSUA/PJSUA2 level, or directly using `pjlib-util/stun_simple`
        API.

    CVE-2022-39244

        The embedded copy of pjproject is affected by this CVE.
        The PJSIP parser, PJMEDIA RTP decoder, and PJMEDIA SDP parser are affeced
        by a buffer overflow vulnerability. Users connecting to untrusted clients
        are at risk.

    CVE-2023-27585

        The embedded copy of pjproject is affected by this CVE.
        A buffer overflow vulnerability affects applications that use PJSIP DNS
        resolver.

    For Debian 11 bullseye, these problems have been fixed in version
    20210112.2.b757bac~ds1-1+deb11u1.

    We recommend that you upgrade your ring packages.

    For the detailed security status of ring please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/ring

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ring");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32686");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37706");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43299");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43300");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43301");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43302");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43303");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43845");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23537");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23547");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23608");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24754");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24764");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24793");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27585");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ring");
  script_set_attribute(attribute:"solution", value:
"Upgrade the jami packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37706");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39244");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jami");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jami-daemon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'jami', 'reference': '20210112.2.b757bac~ds1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'jami-daemon', 'reference': '20210112.2.b757bac~ds1-1+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jami / jami-daemon');
}
