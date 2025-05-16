#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202312-14.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187305);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/26");

  script_cve_id(
    "CVE-2021-33815",
    "CVE-2021-38171",
    "CVE-2021-38291",
    "CVE-2022-1475",
    "CVE-2022-3964",
    "CVE-2022-3965",
    "CVE-2022-48434"
  );

  script_name(english:"GLSA-202312-14 : FFmpeg: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202312-14 (FFmpeg: Multiple Vulnerabilities)

  - dwa_uncompress in libavcodec/exr.c in FFmpeg 4.4 allows an out-of-bounds array access because dc_count is
    not strictly checked. (CVE-2021-33815)

  - adts_decode_extradata in libavformat/adtsenc.c in FFmpeg 4.4 does not check the init_get_bits return
    value, which is a necessary step because the second argument to init_get_bits can be crafted.
    (CVE-2021-38171)

  - FFmpeg version (git commit de8e6e67e7523e48bb27ac224a0b446df05e1640) suffers from a an assertion failure
    at src/libavutil/mathematics.c. (CVE-2021-38291)

  - An integer overflow vulnerability was found in FFmpeg versions before 4.4.2 and before 5.0.1 in
    g729_parse() in llibavcodec/g729_parser.c when processing a specially crafted file. (CVE-2022-1475)

  - A vulnerability classified as problematic has been found in ffmpeg. This affects an unknown part of the
    file libavcodec/rpzaenc.c of the component QuickTime RPZA Video Encoder. The manipulation of the argument
    y_size leads to out-of-bounds read. It is possible to initiate the attack remotely. The name of the patch
    is 92f9b28ed84a77138105475beba16c146bdaf984. It is recommended to apply a patch to fix this issue. The
    associated identifier of this vulnerability is VDB-213543. (CVE-2022-3964)

  - A vulnerability classified as problematic was found in ffmpeg. This vulnerability affects the function
    smc_encode_stream of the file libavcodec/smcenc.c of the component QuickTime Graphics Video Encoder. The
    manipulation of the argument y_size leads to out-of-bounds read. The attack can be initiated remotely. The
    name of the patch is 13c13109759090b7f7182480d075e13b36ed8edd. It is recommended to apply a patch to fix
    this issue. The identifier of this vulnerability is VDB-213544. (CVE-2022-3965)

  - libavcodec/pthread_frame.c in FFmpeg before 5.1.2, as used in VLC and other products, leaves stale hwaccel
    state in worker threads, which allows attackers to trigger a use-after-free and execute arbitrary code in
    some circumstances (e.g., hardware re-initialization upon a mid-video SPS change when Direct3D11 is used).
    (CVE-2022-48434)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202312-14");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=795696");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=842267");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=881523");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=903805");
  script_set_attribute(attribute:"solution", value:
"All FFmpeg 4 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-video/ffmpeg-4.4.3
        
All FFmpeg 6 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-video/ffmpeg-6.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38171");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'media-video/ffmpeg',
    'unaffected' : make_list("ge 4.4.3", "lt 4.0.0"),
    'vulnerable' : make_list("lt 4.4.3")
  },
  {
    'name' : 'media-video/ffmpeg',
    'unaffected' : make_list("ge 6.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'FFmpeg');
}
