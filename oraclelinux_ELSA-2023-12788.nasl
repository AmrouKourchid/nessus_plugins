#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-12788.
##

include('compat.inc');

if (description)
{
  script_id(181323);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2022-40982", "CVE-2023-4039");

  script_name(english:"Oracle Linux 8 / 9 : gcc (ELSA-2023-12788)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2023-12788 advisory.

    - CVE-2023-4039 GCC mitigation.
      Orabug 35751743.
      Includes removal of aarch64-preserve-args.patch.
    - CVE-2022-40982 'Intel Downfall' mitigation.
      Orabug 35751810.
      Add two patches originally from GCC upstream releases/gcc-11 branch.
      with major adjustment.
      gcc11-downfall-disable-gather-in-vec.patch
      gcc11-downfall-support-mno-gather.patch
      Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>

    gcc [el9]
    - CVE-2023-4039 GCC mitigation.
      Orabug 35751837.
    - CVE-2022-40982 'Intel Downfall' mitigation.
      Orabug 35751842.
      Add two patches originally from GCC upstream releases/gcc-11 branch.
      gcc11-downfall-disable-gather-in-vec.patch
      gcc11-downfall-support-mno-gather.patch
    Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>

    gcc-toolset-11-gcc [el8]
    - CVE-2023-4039 GCC mitigation.
      Orabug 35751885.
    - CVE-2022-40982 'Intel Downfall' mitigation.
      Orabug 35751901.
      Add two patches originally from GCC upstream releases/gcc-11 branch.
      gcc11-downfall-disable-gather-in-vec.patch
      gcc11-downfall-support-mno-gather.patch
      Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>

    gcc-toolset-12-gcc [el8/el9]
    - CVE-2023-4039 GCC mitigation.
      Orabug 35751931.
    - CVE-2022-40982 'Intel Downfall' mitigation.
      Orabug 35751938.
      Add two patches originally from GCC upstream releases/gcc-11 branch.
      gcc12-downfall-disable-gather-in-vec.patch
      gcc12-downfall-support-mno-gather.patch

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-12788.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40982");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:8:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:2:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-plugin-annobin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-gcc-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libasan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libatomic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libgccjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libgccjit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libgccjit-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-liblsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libtsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-11-libubsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-gcc-plugin-annobin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libasan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libatomic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libgccjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libgccjit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libgccjit-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-liblsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libtsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-libubsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-12-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libasan6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libasan8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgccjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgccjit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgomp-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:liblsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtsan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libubsan");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^(8|9)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8 / 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'cpp-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-annobin-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-c++-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-gdb-plugin-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-gfortran-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-plugin-devel-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libasan-devel-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libatomic-devel-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libgccjit-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libgccjit-devel-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libgccjit-docs-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libitm-devel-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-liblsan-devel-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libstdc++-devel-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libstdc++-docs-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libtsan-devel-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libubsan-devel-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-c++-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-gfortran-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-annobin-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-devel-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libasan-devel-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libatomic-devel-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-devel-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-docs-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libitm-devel-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-liblsan-devel-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-devel-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-docs-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libtsan-devel-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libubsan-devel-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan6-11.2.1-9.1.0.6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan8-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan2-12.2.1-7.4.0.2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-8.5.0-18.0.5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-offload-nvptx-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-annobin-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-c++-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-gdb-plugin-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-gfortran-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-plugin-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libasan-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libatomic-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libgccjit-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libgccjit-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libgccjit-docs-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libitm-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-liblsan-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libquadmath-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libstdc++-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libstdc++-docs-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libtsan-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libubsan-devel-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-c++-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-gfortran-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-annobin-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libasan-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libatomic-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-docs-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libitm-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-liblsan-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libquadmath-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-docs-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libtsan-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libubsan-devel-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-offload-nvptx-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan6-11.2.1-9.1.0.6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan8-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan2-12.2.1-7.4.0.2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-8.5.0-18.0.5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-offload-nvptx-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-annobin-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-c++-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-gdb-plugin-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-gfortran-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-gcc-plugin-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libasan-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libatomic-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libgccjit-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libgccjit-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libgccjit-docs-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libitm-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-liblsan-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libquadmath-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libstdc++-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libstdc++-docs-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libtsan-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-11-libubsan-devel-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-c++-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-gfortran-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-annobin-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libasan-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libatomic-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-docs-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libitm-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-liblsan-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libquadmath-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-docs-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libtsan-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libubsan-devel-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-offload-nvptx-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan6-11.2.1-9.1.0.6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan8-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-offload-nvptx-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan2-12.2.1-7.4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-8.5.0-18.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-annobin-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-c++-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-gfortran-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-annobin-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-devel-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libasan-devel-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libatomic-devel-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-devel-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-docs-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libitm-devel-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-liblsan-devel-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-devel-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-docs-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libtsan-devel-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libubsan-devel-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan8-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan2-12.2.1-7.4.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-11.3.1-4.3.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-offload-nvptx-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-annobin-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-c++-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-gfortran-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-annobin-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libasan-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libatomic-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-docs-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libitm-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-liblsan-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libquadmath-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-docs-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libtsan-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libubsan-devel-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-offload-nvptx-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan8-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-offload-nvptx-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan2-12.2.1-7.4.0.2.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-11.3.1-4.3.0.4.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-offload-nvptx-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-annobin-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-c++-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-gfortran-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-annobin-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-gcc-plugin-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libasan-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libatomic-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libgccjit-docs-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libitm-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-liblsan-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libquadmath-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libstdc++-docs-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libtsan-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-libubsan-devel-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-12-offload-nvptx-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan8-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-offload-nvptx-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan2-12.2.1-7.4.0.2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-11.3.1-4.3.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cpp / gcc / gcc-c++ / etc');
}
