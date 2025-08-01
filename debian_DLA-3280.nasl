#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3280. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170563);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-21596",
    "CVE-2020-21597",
    "CVE-2020-21598",
    "CVE-2022-43235",
    "CVE-2022-43236",
    "CVE-2022-43237",
    "CVE-2022-43238",
    "CVE-2022-43239",
    "CVE-2022-43240",
    "CVE-2022-43241",
    "CVE-2022-43242",
    "CVE-2022-43243",
    "CVE-2022-43244",
    "CVE-2022-43245",
    "CVE-2022-43248",
    "CVE-2022-43249",
    "CVE-2022-43250",
    "CVE-2022-43252",
    "CVE-2022-43253",
    "CVE-2022-47655"
  );

  script_name(english:"Debian dla-3280 : libde265-0 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3280 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3280-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    January 24, 2023                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libde265
    Version        : 1.0.3-1+deb10u2
    CVE ID         : CVE-2020-21596 CVE-2020-21597 CVE-2020-21598 CVE-2022-43235
                     CVE-2022-43236 CVE-2022-43237 CVE-2022-43238 CVE-2022-43239
                     CVE-2022-43240 CVE-2022-43241 CVE-2022-43242 CVE-2022-43243
                     CVE-2022-43244 CVE-2022-43245 CVE-2022-43248 CVE-2022-43249
                     CVE-2022-43250 CVE-2022-43252 CVE-2022-43253 CVE-2022-47655
    Debian Bug     : 1025816 1027179 1029357 1029397

    Multiple issues were found in libde265, an open source implementation
    of the H.265 video codec, which may result in denial of service or have
    unspecified other impact.


    CVE-2020-21596

        libde265 v1.0.4 contains a global buffer overflow in the
        decode_CABAC_bit function, which can be exploited via a crafted a
        file.

    CVE-2020-21597

        libde265 v1.0.4 contains a heap buffer overflow in the mc_chroma
        function, which can be exploited via a crafted a file.

    CVE-2020-21598

        libde265 v1.0.4 contains a heap buffer overflow in the
        ff_hevc_put_unweighted_pred_8_sse function, which can be exploited
        via a crafted a file.

    CVE-2022-43235

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via ff_hevc_put_hevc_epel_pixels_8_sse in
        sse-motion.cc. This vulnerability allows attackers to cause a Denial
        of Service (DoS) via a crafted video file.

    CVE-2022-43236

        Libde265 v1.0.8 was discovered to contain a stack-buffer-overflow
        vulnerability via put_qpel_fallback<unsigned short> in
        fallback-motion.cc. This vulnerability allows attackers to cause a
        Denial of Service (DoS) via a crafted video file.

    CVE-2022-43237

        Libde265 v1.0.8 was discovered to contain a stack-buffer-overflow
        vulnerability via void put_epel_hv_fallback<unsigned short> in
        fallback-motion.cc. This vulnerability allows attackers to cause a
        Denial of Service (DoS) via a crafted video file.

    CVE-2022-43238

        Libde265 v1.0.8 was discovered to contain an unknown crash via
        ff_hevc_put_hevc_qpel_h_3_v_3_sse in sse-motion.cc. This
        vulnerability allows attackers to cause a Denial of Service (DoS)
        via a crafted video file.

    CVE-2022-43239

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via mc_chroma<unsigned short> in motion.cc. This
        vulnerability allows attackers to cause a Denial of Service (DoS)
        via a crafted video file.

    CVE-2022-43240

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via ff_hevc_put_hevc_qpel_h_2_v_1_sse in
        sse-motion.cc. This vulnerability allows attackers to cause a Denial
        of Service (DoS) via a crafted video file.

    CVE-2022-43241

        Libde265 v1.0.8 was discovered to contain an unknown crash via
        ff_hevc_put_hevc_qpel_v_3_8_sse in sse-motion.cc. This vulnerability
        allows attackers to cause a Denial of Service (DoS) via a crafted
        video file.

    CVE-2022-43242

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via mc_luma<unsigned char> in motion.cc. This
        vulnerability allows attackers to cause a Denial of Service (DoS)
        via a crafted video file.

    CVE-2022-43243

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via ff_hevc_put_weighted_pred_avg_8_sse in
        sse-motion.cc. This vulnerability allows attackers to cause a Denial
        of Service (DoS) via a crafted video file.

    CVE-2022-43244

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via put_qpel_fallback<unsigned short> in
        fallback-motion.cc. This vulnerability allows attackers to cause a
        Denial of Service (DoS) via a crafted video file.

    CVE-2022-43245

        Libde265 v1.0.8 was discovered to contain a segmentation violation
        via apply_sao_internal<unsigned short> in sao.cc. This vulnerability
        allows attackers to cause a Denial of Service (DoS) via a crafted
        video file.

    CVE-2022-43248

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via put_weighted_pred_avg_16_fallback in
        fallback-motion.cc. This vulnerability allows attackers to cause a
        Denial of Service (DoS) via a crafted video file.

    CVE-2022-43249

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via put_epel_hv_fallback<unsigned short> in
        fallback-motion.cc.  This vulnerability allows attackers to cause a
        Denial of Service (DoS) via a crafted video file.

    CVE-2022-43250

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via put_qpel_0_0_fallback_16 in fallback-motion.cc.
        This vulnerability allows attackers to cause a Denial of Service
        (DoS) via a crafted video file.

    CVE-2022-43252

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via put_epel_16_fallback in fallback-motion.cc. This
        vulnerability allows attackers to cause a Denial of Service (DoS)
        via a crafted video file.

    CVE-2022-43253

        Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
        vulnerability via put_unweighted_pred_16_fallback in
        fallback-motion.cc. This vulnerability allows attackers to cause a
        Denial of Service (DoS) via a crafted video file.

    CVE-2022-47655

        Libde265 1.0.9 is vulnerable to Buffer Overflow in function void
        put_qpel_fallback<unsigned short>

    For Debian 10 buster, these problems have been fixed in version
    1.0.3-1+deb10u2.

    We recommend that you upgrade your libde265 packages.

    For the detailed security status of libde265 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libde265

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libde265");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21596");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43235");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43236");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43237");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43238");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43239");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43240");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43241");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43242");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43243");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43245");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43248");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43249");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43250");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43252");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43253");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47655");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libde265");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libde265-0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-21598");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libde265-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libde265-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libde265-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libde265-0', 'reference': '1.0.3-1+deb10u2'},
    {'release': '10.0', 'prefix': 'libde265-dev', 'reference': '1.0.3-1+deb10u2'},
    {'release': '10.0', 'prefix': 'libde265-examples', 'reference': '1.0.3-1+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libde265-0 / libde265-dev / libde265-examples');
}
