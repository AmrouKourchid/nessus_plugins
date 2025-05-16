#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4095. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(233545);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/29");

  script_cve_id(
    "CVE-2023-34440",
    "CVE-2023-43758",
    "CVE-2024-24582",
    "CVE-2024-28047",
    "CVE-2024-28127",
    "CVE-2024-29214",
    "CVE-2024-31068",
    "CVE-2024-31157",
    "CVE-2024-36293",
    "CVE-2024-37020",
    "CVE-2024-39279",
    "CVE-2024-39355"
  );

  script_name(english:"Debian dla-4095 : intel-microcode - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-4095 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4095-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    March 29, 2025                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : intel-microcode
    Version        : 3.20250211.1~deb11u1
    CVE ID         : CVE-2023-34440 CVE-2023-43758 CVE-2024-24582 CVE-2024-28047
                     CVE-2024-28127 CVE-2024-29214 CVE-2024-31068 CVE-2024-31157
                     CVE-2024-36293 CVE-2024-37020 CVE-2024-39279 CVE-2024-39355
    Debian Bug     : 1095805

    Microcode updates has been released for Intel(R) processors, addressing
    multiple potential vulnerabilties that may allow local privilege escalation,
    denial of service or information disclosure.

    CVE-2023-34440 (INTEL-SA-01139)

        Improper input validation in UEFI firmware for some Intel(R) Processors
        may allow a privileged user to potentially enable escalation of
        privilege via local access.

    CVE-2023-43758 (INTEL-SA-01139)

        Improper input validation in UEFI firmware for some Intel(R) processors
        may allow a privileged user to potentially enable escalation of
        privilege via local access.

    CVE-2024-24582 (INTEL-SA-01139)

        Improper input validation in XmlCli feature for UEFI firmware for some
        Intel(R) processors may allow privileged user to potentially enable
        escalation of privilege via local access.

    CVE-2024-28047 (INTEL-SA-01139)

        Improper input validation in UEFI firmware for some Intel(R) Processors
        may allow a privileged user to potentially enable information disclosure
        via local access.

    CVE-2024-28127 (INTEL-SA-01139)

        Improper input validation in UEFI firmware for some Intel(R) Processors
        may allow a privileged user to potentially enable escalation of
        privilege via local access.

    CVE-2024-29214 (INTEL-SA-01139)

        Improper input validation in UEFI firmware CseVariableStorageSmm for
        some Intel(R) Processors may allow a privileged user to potentially
        enable escalation of privilege via local access.

    CVE-2024-31068 (INTEL-SA-01166)

        Improper Finite State Machines (FSMs) in Hardware Logic for some
        Intel(R) Processors may allow privileged user to potentially enable
        denial of service via local access.

    CVE-2024-31157 (INTEL-SA-01139)

        Improper initialization in UEFI firmware OutOfBandXML module in some
        Intel(R) Processors may allow a privileged user to potentially enable
        information disclosure via local access.

    CVE-2024-36293 (INTEL-SA-01213)

        Improper access control in the EDECCSSA user leaf function for some
        Intel(R) Processors with Intel(R) SGX may allow an authenticated user to
        potentially enable denial of service via local access.

    CVE-2024-37020 (INTEL-SA-01194)

        Sequence of processor instructions leads to unexpected behavior in the
        Intel(R) DSA V1.0 for some Intel(R) Xeon(R) Processors may allow an
        authenticated user to potentially enable denial of service via local
        access.

    CVE-2024-39279 (INTEL-SA-01139)

        Insufficient granularity of access control in UEFI firmware in some
        Intel(R) processors may allow a authenticated user to potentially enable
        denial of service via local access.

    CVE-2024-39355 (INTEL-SA-01228)

        Improper handling of physical or environmental conditions in some
        Intel(R) Processors may allow an authenticated user to enable denial of
        service via local access.

    For Debian 11 bullseye, these problems have been fixed in version
    3.20250211.1~deb11u1.

    We recommend that you upgrade your intel-microcode packages.

    For the detailed security status of intel-microcode please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/intel-microcode

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/intel-microcode
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?019586d4");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34440");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-43758");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24582");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-28047");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-28127");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-29214");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31068");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31157");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36293");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-37020");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39279");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-39355");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/intel-microcode");
  script_set_attribute(attribute:"solution", value:
"Upgrade the intel-microcode packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43758");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-29214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:intel-microcode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'intel-microcode', 'reference': '3.20250211.1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'intel-microcode');
}
