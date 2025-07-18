#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0232.
#

include('compat.inc');

if (description)
{
  script_id(110791);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id("CVE-2018-3639", "CVE-2018-3665");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2018-0232) (Spectre)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=b059d1de3b211fe5582c63f64b4822b9f85eafd2

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xend: fix memory leak of XendConfig.XendConfig object
    (Manjunath Patil) [Orabug: 28165871]

  - x86/HVM: Restart ioreq processing state machine (Boris
    Ostrovsky) 

  - x86/spec-ctrl: Mitigations for LazyFPU (Andrew Cooper)
    [Orabug: 28135175] (CVE-2018-3665)

  - x86: Support fully eager FPU context switching (Andrew
    Cooper) [Orabug: 28135175] (CVE-2018-3665)

  - svm: fix incorrect TSC scaling (Haozhong Zhang) [Orabug:
    27182906]

  - x86/AMD-ucode: correct multiple container handling (Jan
    Beulich) 

  - x86, amd_ucode: fix coverity issues found in
    cpu_request_microcode (Aravind Gopalakrishnan) [Orabug:
    28157269]

  - [xenmicrocode] Fix error reporting on successful return
    from tool (Ross Philipson) [Orabug: 28128754]

  - x86: correct default_xen_spec_ctrl calculation (Jan
    Beulich) [Orabug: 28035001]

  - x86/msr: Virtualise MSR_SPEC_CTRL.SSBD for guests to use
    (Andrew Cooper) [Orabug: 28035001] (CVE-2018-3639)

  - x86/Intel: Mitigations for GPZ SP4 - Speculative Store
    Bypass (Andrew Cooper) [Orabug: 28035001]
    (CVE-2018-3639)

  - x86/AMD: Mitigations for GPZ SP4 - Speculative Store
    Bypass (Andrew Cooper) [Orabug: 28035001]
    (CVE-2018-3639)

  - x86/spec_ctrl: Introduce a new `spec-ctrl=` command line
    argument to replace `bti=` (Andrew Cooper) [Orabug:
    28035001] (CVE-2018-3639)

  - x86/cpuid: Improvements to guest policies for
    speculative sidechannel features (Andrew Cooper)
    [Orabug: 28035001] (CVE-2018-3639)

  - x86/spec_ctrl: Explicitly set Xen's default
    MSR_SPEC_CTRL value (Andrew Cooper) [Orabug: 28035001]
    (CVE-2018-3639)

  - x86/spec_ctrl: Split X86_FEATURE_SC_MSR into PV and HVM
    variants (Andrew Cooper) [Orabug: 28035001]
    (CVE-2018-3639)

  - x86/spec_ctrl: Elide MSR_SPEC_CTRL handling in idle
    context when possible (Andrew Cooper) [Orabug: 28035001]
    (CVE-2018-3639)

  - x86/spec_ctrl: Rename bits of infrastructure to avoid
    NATIVE and VMEXIT (Andrew Cooper) [Orabug: 28035001]
    (CVE-2018-3639)

  - x86/spec_ctrl: Fold the XEN_IBRS_[SET,CLEAR]
    ALTERNATIVES together (Andrew Cooper) [Orabug: 28035001]
    (CVE-2018-3639)

  - x86/spec_ctrl: Merge bti_ist_info and
    use_shadow_spec_ctrl into spec_ctrl_flags (Andrew
    Cooper) [Orabug: 28035001] (CVE-2018-3639)

  - x86/spec_ctrl: Express Xen's choice of MSR_SPEC_CTRL
    value as a variable (Andrew Cooper) [Orabug: 28035001]
    (CVE-2018-3639)

  - x86/spec_ctrl: Read MSR_ARCH_CAPABILITIES only once
    (Andrew Cooper) [Orabug: 28035001] (CVE-2018-3639)

  - x86/spec_ctrl: Assume that STIBP feature is always
    available (Boris Ostrovsky) [Orabug: 28035001]
    (CVE-2018-3639)

  - x86/spec_ctrl: Updates to retpoline-safety decision
    making (Andrew Cooper) [Orabug: 28035001]
    (CVE-2018-3639)

  - Revert 'x86/boot: Disable IBRS in intr/nmi exit path at
    bootup stage' (Boris Ostrovsky) [Orabug: 28035001]
    (CVE-2018-3639)");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-June/000867.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected xen / xen-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3665");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(rpm:"xen-4.4.4-196", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-196.0.1.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-196", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-196.0.1.el6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
