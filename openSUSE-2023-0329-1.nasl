#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0329-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(183956);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/27");

  script_cve_id(
    "CVE-2019-13590",
    "CVE-2021-3643",
    "CVE-2021-23159",
    "CVE-2021-33844",
    "CVE-2021-40426",
    "CVE-2022-31650",
    "CVE-2022-31651",
    "CVE-2023-32627",
    "CVE-2023-34318",
    "CVE-2023-34432"
  );

  script_name(english:"openSUSE 15 Security Update : sox (openSUSE-SU-2023:0329-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0329-1 advisory.

  - An issue was discovered in libsox.a in SoX 14.4.2. In sox-fmt.h (startread function), there is an integer
    overflow on the result of integer addition (wraparound to 0) fed into the lsx_calloc macro that wraps
    malloc. When a NULL pointer is returned, it is used without a prior check that it is a valid pointer,
    leading to a NULL pointer dereference on lsx_readbuf in formats_i.c. (CVE-2019-13590)

  - A vulnerability was found in SoX, where a heap-buffer-overflow occurs in function lsx_read_w_buf() in
    formats_i.c file. The vulnerability is exploitable with a crafted file, that could cause an application to
    crash. (CVE-2021-23159)

  - A floating point exception (divide-by-zero) issue was discovered in SoX in functon startread() of wav.c
    file. An attacker with a crafted wav file, could cause an application to crash. (CVE-2021-33844)

  - A flaw was found in sox 14.4.1. The lsx_adpcm_init function within libsox leads to a global-buffer-
    overflow. This flaw allows an attacker to input a malicious file, leading to the disclosure of sensitive
    information. (CVE-2021-3643)

  - A heap-based buffer overflow vulnerability exists in the sphere.c start_read() functionality of Sound
    Exchange libsox 14.4.2 and master commit 42b3557e. A specially-crafted file can lead to a heap buffer
    overflow. An attacker can provide a malicious file to trigger this vulnerability. (CVE-2021-40426)

  - In SoX 14.4.2, there is a floating-point exception in lsx_aiffstartwrite in aiff.c in libsox.a.
    (CVE-2022-31650)

  - In SoX 14.4.2, there is an assertion failure in rate_init in rate.c in libsox.a. (CVE-2022-31651)

  - A floating point exception vulnerability was found in sox, in the read_samples function at
    sox/src/voc.c:334:18. This flaw can lead to a denial of service. (CVE-2023-32627)

  - A heap buffer overflow vulnerability was found in sox, in the startread function at sox/src/hcom.c:160:41.
    This flaw can lead to a denial of service, code execution, or information disclosure. (CVE-2023-34318)

  - A heap buffer overflow vulnerability was found in sox, in the lsx_readbuf function at
    sox/src/formats_i.c:98:16. This flaw can lead to a denial of service, code execution, or information
    disclosure. (CVE-2023-34432)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212063");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OWH3Y6RJSLCAZ7XAIEM2FMD5E6EQYZM5/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ce9c84e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-40426");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-34318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-34432");
  script_set_attribute(attribute:"solution", value:
"Update the affected libsox3, sox and / or sox-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40426");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3643");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsox3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'libsox3-14.4.2-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sox-14.4.2-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sox-devel-14.4.2-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsox3 / sox / sox-devel');
}
