#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231562);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-53680");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-53680");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipvs: fix UB due to uninitialized
    stack access in ip_vs_protocol_init() Under certain kernel configurations when building with Clang/LLVM,
    the compiler does not generate a return or jump as the terminator instruction for ip_vs_protocol_init(),
    triggering the following objtool warning during build time: vmlinux.o: warning: objtool:
    ip_vs_protocol_init() falls through to next function __initstub__kmod_ip_vs_rr__935_123_ip_vs_rr_init6()
    At runtime, this either causes an oops when trying to load the ipvs module or a boot-time panic if ipvs is
    built-in. This same issue has been reported by the Intel kernel test robot previously. Digging deeper into
    both LLVM and the kernel code reveals this to be a undefined behavior problem. ip_vs_protocol_init() uses
    a on-stack buffer of 64 chars to store the registered protocol names and leaves it uninitialized after
    definition. The function calls strnlen() when concatenating protocol names into the buffer. With
    CONFIG_FORTIFY_SOURCE strnlen() performs an extra step to check whether the last byte of the input char
    buffer is a null character (commit 3009f891bb9f (fortify: Allow strlen() and strnlen() to pass compile-
    time known lengths)). This, together with possibly other configurations, cause the following IR to be
    generated: define hidden i32 @ip_vs_protocol_init() local_unnamed_addr #5 section .init.text align 16
    !kcfi_type !29 { %1 = alloca [64 x i8], align 16 ... 14: ; preds = %11 %15 = getelementptr inbounds i8,
    ptr %1, i64 63 %16 = load i8, ptr %15, align 1 %17 = tail call i1 @llvm.is.constant.i8(i8 %16) %18 = icmp
    eq i8 %16, 0 %19 = select i1 %17, i1 %18, i1 false br i1 %19, label %20, label %23 20: ; preds = %14 %21 =
    call i64 @strlen(ptr noundef nonnull dereferenceable(1) %1) #23 ... 23: ; preds = %14, %11, %20 %24 = call
    i64 @strnlen(ptr noundef nonnull dereferenceable(1) %1, i64 noundef 64) #24 ... } The above code
    calculates the address of the last char in the buffer (value %15) and then loads from it (value %16).
    Because the buffer is never initialized, the LLVM GVN pass marks value %16 as undefined: %13 =
    getelementptr inbounds i8, ptr %1, i64 63 br i1 undef, label %14, label %17 This gives later passes (SCCP,
    in particular) more DCE opportunities by propagating the undef value further, and eventually removes
    everything after the load on the uninitialized stack location: define hidden i32 @ip_vs_protocol_init()
    local_unnamed_addr #0 section .init.text align 16 !kcfi_type !11 { %1 = alloca [64 x i8], align 16 ...
    12: ; preds = %11 %13 = getelementptr inbounds i8, ptr %1, i64 63 unreachable } In this way, the generated
    native code will just fall through to the next function, as LLVM does not generate any code for the
    unreachable IR instruction and leaves the function without a terminator. Zero the on-stack buffer to avoid
    this possible UB. (CVE-2024-53680)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53680");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "kernel",
     "kernel-rt"
    ],
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "9"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
