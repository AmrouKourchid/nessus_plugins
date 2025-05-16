#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202405-05.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(194979);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/04");

  script_cve_id(
    "CVE-2022-38600",
    "CVE-2022-38850",
    "CVE-2022-38851",
    "CVE-2022-38853",
    "CVE-2022-38855",
    "CVE-2022-38856",
    "CVE-2022-38858",
    "CVE-2022-38860",
    "CVE-2022-38861",
    "CVE-2022-38862",
    "CVE-2022-38863",
    "CVE-2022-38864",
    "CVE-2022-38865",
    "CVE-2022-38866"
  );

  script_name(english:"GLSA-202405-05 : MPlayer: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202405-05 (MPlayer: Multiple Vulnerabilities)

  - Mplayer SVN-r38374-13.0.1 is vulnerable to Memory Leak via vf.c and vf_vo.c. (CVE-2022-38600)

  - The MPlayer Project mencoder SVN-r38374-13.0.1 is vulnerable to Divide By Zero via the function config ()
    of llibmpcodecs/vf_scale.c. (CVE-2022-38850)

  - Certain The MPlayer Project products are vulnerable to Out-of-bounds Read via function read_meta_record()
    of mplayer/libmpdemux/asfheader.c. This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
    (CVE-2022-38851)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via function
    asf_init_audio_stream() of libmpdemux/asfheader.c. This affects mplayer SVN-r38374-13.0.1 and mencoder
    SVN-r38374-13.0.1. (CVE-2022-38853)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via function gen_sh_video () of
    mplayer/libmpdemux/demux_mov.c. This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
    (CVE-2022-38855)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via function mov_build_index() of
    libmpdemux/demux_mov.c. This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
    (CVE-2022-38856, CVE-2022-38858)

  - Certain The MPlayer Project products are vulnerable to Divide By Zero via function demux_open_avi() of
    libmpdemux/demux_avi.c which affects mencoder. This affects mplayer SVN-r38374-13.0.1 and mencoder
    SVN-r38374-13.0.1. (CVE-2022-38860)

  - The MPlayer Project mplayer SVN-r38374-13.0.1 is vulnerable to memory corruption via function
    free_mp_image() of libmpcodecs/mp_image.c. (CVE-2022-38861)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via function play() of
    libaf/af.c:639. This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1. (CVE-2022-38862)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via function mp_getbits() of
    libmpdemux/mpeg_hdr.c which affects mencoder and mplayer. This affects mecoder SVN-r38374-13.0.1 and
    mplayer SVN-r38374-13.0.1. (CVE-2022-38863)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via the function mp_unescape03() of
    libmpdemux/mpeg_hdr.c. This affects mencoder SVN-r38374-13.0.1 and mplayer SVN-r38374-13.0.1.
    (CVE-2022-38864)

  - Certain The MPlayer Project products are vulnerable to Divide By Zero via the function
    demux_avi_read_packet of libmpdemux/demux_avi.c. This affects mplyer SVN-r38374-13.0.1 and mencoder
    SVN-r38374-13.0.1. (CVE-2022-38865)

  - Certain The MPlayer Project products are vulnerable to Buffer Overflow via read_avi_header() of
    libmpdemux/aviheader.c . This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
    (CVE-2022-38866)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202405-05");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=870406");
  script_set_attribute(attribute:"solution", value:
"All MPlayer users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-video/mplayer-1.5");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'media-video/mplayer',
    'unaffected' : make_list("ge 1.5"),
    'vulnerable' : make_list("lt 1.5")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MPlayer');
}
