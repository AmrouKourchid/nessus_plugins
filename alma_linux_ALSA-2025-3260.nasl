#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2025:3260.
##

include('compat.inc');

if (description)
{
  script_id(233663);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id("CVE-2025-21785");
  script_xref(name:"ALSA", value:"2025:3260");
  script_xref(name:"RHSA", value:"2025:3260");

  script_name(english:"AlmaLinux 8 : kernel (ALSA-2025:3260)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2025:3260 advisory.

    * kernel: arm64: cacheinfo: Avoid out-of-bounds write to cacheinfo array (CVE-2025-21785)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2025-3260.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:3260");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21785");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2025-21785');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2025:3260');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'bpftool-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'bpftool-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'bpftool-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-abi-stablelists-4.18.0-553.46.1.el8_10', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.46.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.46.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.46.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.46.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
