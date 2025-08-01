#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5653. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192900);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2023-32650",
    "CVE-2023-34087",
    "CVE-2023-34436",
    "CVE-2023-35004",
    "CVE-2023-35057",
    "CVE-2023-35128",
    "CVE-2023-35702",
    "CVE-2023-35703",
    "CVE-2023-35704",
    "CVE-2023-35955",
    "CVE-2023-35956",
    "CVE-2023-35957",
    "CVE-2023-35958",
    "CVE-2023-35959",
    "CVE-2023-35960",
    "CVE-2023-35961",
    "CVE-2023-35962",
    "CVE-2023-35963",
    "CVE-2023-35964",
    "CVE-2023-35969",
    "CVE-2023-35970",
    "CVE-2023-35989",
    "CVE-2023-35992",
    "CVE-2023-35994",
    "CVE-2023-35995",
    "CVE-2023-35996",
    "CVE-2023-35997",
    "CVE-2023-36746",
    "CVE-2023-36747",
    "CVE-2023-36861",
    "CVE-2023-36864",
    "CVE-2023-36915",
    "CVE-2023-36916",
    "CVE-2023-37282",
    "CVE-2023-37416",
    "CVE-2023-37417",
    "CVE-2023-37418",
    "CVE-2023-37419",
    "CVE-2023-37420",
    "CVE-2023-37442",
    "CVE-2023-37443",
    "CVE-2023-37444",
    "CVE-2023-37445",
    "CVE-2023-37446",
    "CVE-2023-37447",
    "CVE-2023-37573",
    "CVE-2023-37574",
    "CVE-2023-37575",
    "CVE-2023-37576",
    "CVE-2023-37577",
    "CVE-2023-37578",
    "CVE-2023-37921",
    "CVE-2023-37922",
    "CVE-2023-37923",
    "CVE-2023-38583",
    "CVE-2023-38618",
    "CVE-2023-38619",
    "CVE-2023-38620",
    "CVE-2023-38621",
    "CVE-2023-38622",
    "CVE-2023-38623",
    "CVE-2023-38648",
    "CVE-2023-38649",
    "CVE-2023-38650",
    "CVE-2023-38651",
    "CVE-2023-38652",
    "CVE-2023-38653",
    "CVE-2023-38657",
    "CVE-2023-39234",
    "CVE-2023-39235",
    "CVE-2023-39270",
    "CVE-2023-39271",
    "CVE-2023-39272",
    "CVE-2023-39273",
    "CVE-2023-39274",
    "CVE-2023-39275",
    "CVE-2023-39316",
    "CVE-2023-39317",
    "CVE-2023-39413",
    "CVE-2023-39414",
    "CVE-2023-39443",
    "CVE-2023-39444"
  );

  script_name(english:"Debian dsa-5653 : gtkwave - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5653 advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5653-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    April 03, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : gtkwave
    CVE ID         : CVE-2023-32650 CVE-2023-34087 CVE-2023-34436 CVE-2023-35004
                     CVE-2023-35057 CVE-2023-35128 CVE-2023-35702 CVE-2023-35703
                     CVE-2023-35704 CVE-2023-35955 CVE-2023-35956 CVE-2023-35957
                     CVE-2023-35958 CVE-2023-35959 CVE-2023-35960 CVE-2023-35961
                     CVE-2023-35962 CVE-2023-35963 CVE-2023-35964 CVE-2023-35969
                     CVE-2023-35970 CVE-2023-35989 CVE-2023-35992 CVE-2023-35994
                     CVE-2023-35995 CVE-2023-35996 CVE-2023-35997 CVE-2023-36746
                     CVE-2023-36747 CVE-2023-36861 CVE-2023-36864 CVE-2023-36915
                     CVE-2023-36916 CVE-2023-37282 CVE-2023-37416 CVE-2023-37417
                     CVE-2023-37418 CVE-2023-37419 CVE-2023-37420 CVE-2023-37442
                     CVE-2023-37443 CVE-2023-37444 CVE-2023-37445 CVE-2023-37446
                     CVE-2023-37447 CVE-2023-37573 CVE-2023-37574 CVE-2023-37575
                     CVE-2023-37576 CVE-2023-37577 CVE-2023-37578 CVE-2023-37921
                     CVE-2023-37922 CVE-2023-37923 CVE-2023-38583 CVE-2023-38618
                     CVE-2023-38619 CVE-2023-38620 CVE-2023-38621 CVE-2023-38622
                     CVE-2023-38623 CVE-2023-38648 CVE-2023-38649 CVE-2023-38650
                     CVE-2023-38651 CVE-2023-38652 CVE-2023-38653 CVE-2023-38657
                     CVE-2023-39234 CVE-2023-39235 CVE-2023-39270 CVE-2023-39271
                     CVE-2023-39272 CVE-2023-39273 CVE-2023-39274 CVE-2023-39275
                     CVE-2023-39316 CVE-2023-39317 CVE-2023-39413 CVE-2023-39414
                     CVE-2023-39443 CVE-2023-39444

    Claudio Bozzato discovered multiple security issues in gtkwave, a file
    waveform viewer for VCD (Value Change Dump) files, which may result in the
    execution of arbitrary code if malformed files are opened.

    For the oldstable distribution (bullseye), these problems have been fixed
    in version 3.3.104+really3.3.118-0+deb11u1.

    For the stable distribution (bookworm), these problems have been fixed in
    version 3.3.118-0.1~deb12u1.

    We recommend that you upgrade your gtkwave packages.

    For the detailed security status of gtkwave please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/gtkwave

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQIzBAEBCgAdFiEEtuYvPRKsOElcDakFEMKTtsN8TjYFAmYNpa8ACgkQEMKTtsN8
    TjaBoRAAm9RrMuWHsKODDA8KffviTPutfYnisOLvciRUZqUHbvYQExE0o/G/JMUh
    21d80NA0jdkZgkGePfnoLRKy95fGu6hL0jgNBt8A/Irmx+uji00MjD+sFAAH42Zm
    DrrKRRmDmUywuOyNVWDm2Zr0LlbjAEvXmdwA6bRO6CueaWGYXYuTn3JQZCUNfsHr
    ciLi6qY5LsR7kEH866ue9PqDxb8Zfmnqm+C/OZZQT3yevXwENANkXR731O7tLuYh
    LWr4WC9DfXzfyG5MYQkbQ989XhUUCPBOYfZIRCqAuh45lFrorNGY7WE+DtLgdeoM
    q9DlRylsTuMW38A+AtON9TnH4o8fXQWoLI+g4MoVddxmJucDrTnBVESnqIMXSxh+
    YZ6zCNcpRZWdviYxvLXQsbqiE/29XPpxkkSyFvvQumnSRILhgyjF8p+urUbHN6/S
    8dF7TEa2lAZ0aQcKiz4xXFSlbGGjKx236CKuW8RYTpTc+Sp/x+1RxeF8cw00tfKZ
    Rl2/1BsAbI4bg/Mvf1XwmH5GM4OQB8O3yQIgaU880rSnCyP+S4F8uAR+09JoOSdc
    Ab+sm8qDvQjrh+qJ0meU75mWQI8eiEczhdY+DtB+mtfHd8GIjNDaNM7u7vHTHA9w
    QAitcjd/hlMhBtYyP8aZzUpSYMfA6AjySmwDFLU/URgKi687yWM=
    =Dwin
    -----END PGP SIGNATURE-----



Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/gtkwave");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32650");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34087");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-34436");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35004");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35057");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35128");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35702");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35703");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35704");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35955");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35956");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35957");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35958");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35959");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35960");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35961");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35962");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35963");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35964");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35969");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35970");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35992");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35994");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35995");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35996");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-35997");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36746");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36747");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36861");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36864");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36915");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37416");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37417");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37418");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37419");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37420");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37442");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37443");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37444");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37445");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37446");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37447");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37573");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37574");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37575");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37576");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37577");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37578");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37921");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37922");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-37923");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38583");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38618");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38619");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38620");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38621");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38648");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38649");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38650");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38651");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38652");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38653");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38657");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39234");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39235");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39270");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39271");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39272");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39273");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39274");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39275");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39316");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39317");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39413");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39414");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39443");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39444");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/gtkwave");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/gtkwave");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gtkwave packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39444");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gtkwave");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gtkwave', 'reference': '3.3.104+really3.3.118-0+deb11u1'},
    {'release': '12.0', 'prefix': 'gtkwave', 'reference': '3.3.118-0.1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gtkwave');
}
