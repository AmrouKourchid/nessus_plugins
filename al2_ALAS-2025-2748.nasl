#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2025-2748.
##

include('compat.inc');

if (description)
{
  script_id(214977);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/01");

  script_cve_id("CVE-2024-47537", "CVE-2024-47540", "CVE-2024-47613");

  script_name(english:"Amazon Linux 2 : gstreamer1-plugins-good (ALAS-2025-2748)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of gstreamer1-plugins-good installed on the remote host is prior to 1.18.4-6. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2025-2748 advisory.

    GStreamer is a library for constructing graphs of media-handling components. The program attempts to
    reallocate the memory pointed to by stream->samples to accommodate stream->n_samples + samples_count
    elements of type QtDemuxSample. The problem is that samples_count is read from the input file. And if this
    value is big enough, this can lead to an integer overflow during the addition. As a consequence,
    g_try_renew might allocate memory for a significantly smaller number of elements than intended. Following
    this, the program iterates through samples_count elements and attempts to write samples_count number of
    elements, potentially exceeding the actual allocated memory size and causing an OOB-write. This
    vulnerability is fixed in 1.24.10. (CVE-2024-47537)

    GStreamer is a library for constructing graphs of media-handling components. An uninitialized stack
    variable vulnerability has been identified in the gst_matroska_demux_add_wvpk_header function within
    matroska-demux.c. When size < 4, the program calls gst_buffer_unmap with an uninitialized map variable.
    Then, in the gst_memory_unmap function, the program will attempt to unmap the buffer using the
    uninitialized map variable, causing a function pointer hijack, as it will jump to
    mem->allocator->mem_unmap_full or mem->allocator->mem_unmap. This vulnerability could allow an attacker to
    hijack the execution flow, potentially leading to code execution. This vulnerability is fixed in 1.24.10.
    (CVE-2024-47540)

    GStreamer is a library for constructing graphs of media-handling components. A null pointer dereference
    vulnerability has been identified in `gst_gdk_pixbuf_dec_flush` within `gstgdkpixbufdec.c`. This function
    invokes `memcpy`, using `out_pix` as the destination address. `out_pix` is expected to point to the frame
    0 from the frame structure, which is read from the input file. However, in certain situations, it can
    points to a NULL frame, causing the subsequent call to `memcpy` to attempt writing to the null address
    (0x00), leading to a null pointer dereference. This vulnerability can result in a Denial of Service (DoS)
    by triggering a segmentation fault (SEGV). This vulnerability is fixed in 1.24.10. (CVE-2024-47613)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2025-2748.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47537.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47540.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47613.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update gstreamer1-plugins-good' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gstreamer1-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gstreamer1-plugins-good-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gstreamer1-plugins-good-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'gstreamer1-plugins-good-1.18.4-6.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-good-1.18.4-6.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-good-1.18.4-6.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-good-debuginfo-1.18.4-6.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-good-debuginfo-1.18.4-6.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-good-debuginfo-1.18.4-6.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-good-gtk-1.18.4-6.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-good-gtk-1.18.4-6.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-good-gtk-1.18.4-6.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer1-plugins-good / gstreamer1-plugins-good-debuginfo / gstreamer1-plugins-good-gtk");
}
