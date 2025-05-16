#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5070. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157886);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2021-4122");

  script_name(english:"Debian DSA-5070-1 : cryptsetup - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5070
advisory.

    CVE-2021-4122 Milan Broz, its maintainer, discovered an issue in cryptsetup, the disk encryption
    configuration tool for Linux. LUKS2 (an on-disk format) online reencryption is an optional extension to
    allow a user to change the data reencryption key while the data device is available for use during the
    whole reencryption process. An attacker can modify on-disk metadata to simulate decryption in progress
    with crashed (unfinished) reencryption step and persistently decrypt part of the LUKS2 device (LUKS1
    devices are indirectly affected as well, see below). This attack requires repeated physical access to the
    LUKS2 device but no knowledge of user passphrases. The decryption step is performed after a valid user
    activates the device with a correct passphrase and modified metadata. The size of possible decrypted data
    per attack step depends on configured LUKS2 header size (metadata size is configurable for LUKS2). With
    the default LUKS2 parameters (16 MiB header) and only one allocated keyslot (512 bit key for AES-XTS),
    simulated decryption with checksum resilience SHA1 (20 bytes checksum for 4096-byte blocks), the maximal
    decrypted size can be over 3GiB. The attack is not applicable to LUKS1 format, but the attacker can update
    metadata in place to LUKS2 format as an additional step. For such a converted LUKS2 header, the keyslot
    area is limited to decrypted size (with SHA1 checksums) over 300 MiB. LUKS devices that were formatted
    using a cryptsetup binary from Debian Stretch or earlier are using LUKS1. However since Debian Buster the
    default on-disk LUKS format version is LUKS2. In particular, encrypted devices formatted by the Debian
    Buster and Bullseye installers are using LUKS2 by default. Key truncation in dm-integrity This update
    additionaly fixes a key truncation issue for standalone dm-integrity devices using HMAC integrity
    protection. For existing such devices with extra long HMAC keys (typically >106 bytes of length), one
    might need to manually truncate the key using integritysetup(8)'s --integrity-key-size option in order to
    properly map the device under 2:2.3.7-1+deb11u1 and later. Only standalone dm-integrity devices are
    affected. dm-crypt devices, including those using authenticated disk encryption, are unaffected. For the
    oldstable distribution (buster), this problem is not present. For the stable distribution (bullseye), this
    problem has been fixed in version 2:2.3.7-1+deb11u1. We recommend that you upgrade your cryptsetup
    packages. For the detailed security status of cryptsetup please refer to its security tracker page at:
    https://security-tracker.debian.org/tracker/cryptsetup

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1003686");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/cryptsetup");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5070");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4122");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/cryptsetup");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/cryptsetup");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cryptsetup packages.

For the stable distribution (bullseye), this problem has been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4122");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cryptsetup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cryptsetup-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cryptsetup-initramfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cryptsetup-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cryptsetup-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcryptsetup-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcryptsetup12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcryptsetup12-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'cryptsetup', 'reference': '2:2.3.7-1+deb11u1'},
    {'release': '11.0', 'prefix': 'cryptsetup-bin', 'reference': '2:2.3.7-1+deb11u1'},
    {'release': '11.0', 'prefix': 'cryptsetup-initramfs', 'reference': '2:2.3.7-1+deb11u1'},
    {'release': '11.0', 'prefix': 'cryptsetup-run', 'reference': '2:2.3.7-1+deb11u1'},
    {'release': '11.0', 'prefix': 'cryptsetup-udeb', 'reference': '2:2.3.7-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libcryptsetup-dev', 'reference': '2:2.3.7-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libcryptsetup12', 'reference': '2:2.3.7-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libcryptsetup12-udeb', 'reference': '2:2.3.7-1+deb11u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cryptsetup / cryptsetup-bin / cryptsetup-initramfs / cryptsetup-run / etc');
}
