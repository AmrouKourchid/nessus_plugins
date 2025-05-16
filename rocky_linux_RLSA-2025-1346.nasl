#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2025:1346.
##

include('compat.inc');

if (description)
{
  script_id(232931);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id("CVE-2020-11023");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");
  script_xref(name:"RLSA", value:"2025:1346");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RockyLinux 9 : gcc (RLSA-2025:1346)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2025:1346 advisory.

    * jquery: Untrusted code execution via <option> tag in HTML passed to DOM manipulation methods
    (CVE-2020-11023)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2025:1346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1850004");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-gfortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-offload-nvptx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-plugin-annobin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-plugin-annobin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gcc-plugin-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libasan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libatomic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgccjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgccjit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgccjit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgfortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgomp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgomp-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libgomp-offload-nvptx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libitm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:liblsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:liblsan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libquadmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libstdc++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libtsan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libubsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libubsan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'cpp-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'cpp-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'cpp-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'cpp-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'cpp-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'cpp-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'cpp-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'cpp-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-c++-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-c++-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-c++-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-c++-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-c++-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-c++-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-c++-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-c++-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-debugsource-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-debugsource-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-debugsource-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-debugsource-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-gfortran-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-gfortran-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-gfortran-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-gfortran-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-gfortran-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-gfortran-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-gfortran-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-gfortran-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-offload-nvptx-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-offload-nvptx-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-offload-nvptx-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-offload-nvptx-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-annobin-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-annobin-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-annobin-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-annobin-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-annobin-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-annobin-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-annobin-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-annobin-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-devel-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-devel-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-devel-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-devel-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-devel-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-devel-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-devel-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-devel-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gcc-plugin-devel-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libasan-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libasan-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libasan-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libasan-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libasan-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libasan-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libasan-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libasan-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libasan-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libatomic-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libatomic-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libatomic-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libatomic-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libatomic-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libatomic-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libatomic-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libatomic-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libatomic-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgcc-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgcc-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgcc-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgcc-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgcc-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgcc-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgcc-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgcc-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgcc-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-devel-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-devel-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-devel-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-devel-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgccjit-devel-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgfortran-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgfortran-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgfortran-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgfortran-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgfortran-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgfortran-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgfortran-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgfortran-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgfortran-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-offload-nvptx-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-offload-nvptx-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-offload-nvptx-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libgomp-offload-nvptx-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-devel-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-devel-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-devel-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-devel-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libitm-devel-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'liblsan-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'liblsan-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'liblsan-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'liblsan-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'liblsan-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'liblsan-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libquadmath-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libquadmath-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libquadmath-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libquadmath-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libquadmath-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libquadmath-devel-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libquadmath-devel-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libquadmath-devel-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-devel-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-devel-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-devel-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-devel-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-devel-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-docs-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-docs-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-docs-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-docs-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-static-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-static-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-static-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-static-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libstdc++-static-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libtsan-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libtsan-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libtsan-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libtsan-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libtsan-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libtsan-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libubsan-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libubsan-11.5.0-5.el9_5', 'cpu':'i686', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libubsan-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libubsan-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libubsan-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libubsan-debuginfo-11.5.0-5.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libubsan-debuginfo-11.5.0-5.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libubsan-debuginfo-11.5.0-5.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libubsan-debuginfo-11.5.0-5.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cpp / cpp-debuginfo / gcc / gcc-c++ / gcc-c++-debuginfo / etc');
}
