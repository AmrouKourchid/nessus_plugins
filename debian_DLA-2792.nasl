#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2792. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154410);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/28");

  script_cve_id(
    "CVE-2018-20199",
    "CVE-2018-20360",
    "CVE-2019-6956",
    "CVE-2021-32274",
    "CVE-2021-32276",
    "CVE-2021-32277",
    "CVE-2021-32278"
  );

  script_name(english:"Debian DLA-2792-1 : faad2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2792 advisory.

  - A NULL pointer dereference was discovered in ifilter_bank of libfaad/filtbank.c in Freeware Advanced Audio
    Decoder 2 (FAAD2) 2.8.8. The vulnerability causes a segmentation fault and application crash, which leads
    to denial of service because adding to windowed output is mishandled in the ONLY_LONG_SEQUENCE case.
    (CVE-2018-20199)

  - An invalid memory address dereference was discovered in the sbr_process_channel function of
    libfaad/sbr_dec.c in Freeware Advanced Audio Decoder 2 (FAAD2) 2.8.8. The vulnerability causes a
    segmentation fault and application crash, which leads to denial of service. (CVE-2018-20360)

  - An issue was discovered in Freeware Advanced Audio Decoder 2 (FAAD2) 2.8.8. It is a buffer over-read in
    ps_mix_phase in libfaad/ps_dec.c. (CVE-2019-6956)

  - An issue was discovered in faad2 through 2.10.0. A heap-buffer-overflow exists in the function
    sbr_qmf_synthesis_64 located in sbr_qmf.c. It allows an attacker to cause code Execution. (CVE-2021-32274)

  - An issue was discovered in faad2 through 2.10.0. A NULL pointer dereference exists in the function
    get_sample() located in output.c. It allows an attacker to cause Denial of Service. (CVE-2021-32276)

  - An issue was discovered in faad2 through 2.10.0. A heap-buffer-overflow exists in the function
    sbr_qmf_analysis_32 located in sbr_qmf.c. It allows an attacker to cause code Execution. (CVE-2021-32277)

  - An issue was discovered in faad2 through 2.10.0. A heap-buffer-overflow exists in the function
    lt_prediction located in lt_predict.c. It allows an attacker to cause code Execution. (CVE-2021-32278)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/faad2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20199");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20360");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-6956");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32274");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32276");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32277");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32278");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/faad2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the faad2 packages.

For Debian 9 stretch, these problems have been fixed in version 2.8.0~cvs20161113-1+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32278");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:faad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:faad2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfaad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfaad2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'faad', 'reference': '2.8.0~cvs20161113-1+deb9u3'},
    {'release': '9.0', 'prefix': 'faad2-dbg', 'reference': '2.8.0~cvs20161113-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libfaad-dev', 'reference': '2.8.0~cvs20161113-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libfaad2', 'reference': '2.8.0~cvs20161113-1+deb9u3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'faad / faad2-dbg / libfaad-dev / libfaad2');
}
