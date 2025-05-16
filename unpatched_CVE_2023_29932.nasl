#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226192);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-29932");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-29932");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - llvm-project commit fdbc55a5 was discovered to contain a segmentation fault via the component
    mlir::IROperand<mlir::OpOperand. (CVE-2023-29932)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

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
     "bolt-15",
     "clang-13",
     "clang-13-doc",
     "clang-13-examples",
     "clang-14",
     "clang-14-doc",
     "clang-14-examples",
     "clang-15",
     "clang-15-doc",
     "clang-15-examples",
     "clang-format-13",
     "clang-format-14",
     "clang-format-15",
     "clang-tidy-13",
     "clang-tidy-14",
     "clang-tidy-15",
     "clang-tools-13",
     "clang-tools-14",
     "clang-tools-15",
     "clangd-13",
     "clangd-14",
     "clangd-15",
     "libbolt-15-dev",
     "libc++-13-dev",
     "libc++-14-dev",
     "libc++-14-dev-wasm32",
     "libc++-15-dev",
     "libc++1-13",
     "libc++1-14",
     "libc++1-15",
     "libc++abi-13-dev",
     "libc++abi-14-dev",
     "libc++abi-14-dev-wasm32",
     "libc++abi-15-dev",
     "libc++abi1-13",
     "libc++abi1-14",
     "libc++abi1-15",
     "libclang-13-dev",
     "libclang-14-dev",
     "libclang-15-dev",
     "libclang-common-13-dev",
     "libclang-common-14-dev",
     "libclang-common-15-dev",
     "libclang-cpp13",
     "libclang-cpp13-dev",
     "libclang-cpp14",
     "libclang-cpp14-dev",
     "libclang-cpp15",
     "libclang-cpp15-dev",
     "libclang-rt-14-dev",
     "libclang-rt-14-dev-wasm32",
     "libclang-rt-14-dev-wasm64",
     "libclang1-13",
     "libclang1-14",
     "libclang1-15",
     "libclc-13",
     "libclc-13-dev",
     "libclc-14",
     "libclc-14-dev",
     "libclc-15",
     "libclc-15-dev",
     "libfuzzer-13-dev",
     "libfuzzer-14-dev",
     "libfuzzer-15-dev",
     "liblld-13",
     "liblld-13-dev",
     "liblld-14",
     "liblld-14-dev",
     "liblld-15",
     "liblld-15-dev",
     "liblldb-13",
     "liblldb-13-dev",
     "liblldb-14",
     "liblldb-14-dev",
     "liblldb-15",
     "liblldb-15-dev",
     "libllvm-13-ocaml-dev",
     "libllvm-14-ocaml-dev",
     "libllvm-15-ocaml-dev",
     "libllvm13",
     "libllvm14",
     "libllvm15",
     "libmlir-13",
     "libmlir-13-dev",
     "libmlir-14",
     "libmlir-14-dev",
     "libmlir-15",
     "libmlir-15-dev",
     "libomp-13-dev",
     "libomp-13-doc",
     "libomp-14-dev",
     "libomp-14-doc",
     "libomp-15-dev",
     "libomp-15-doc",
     "libomp5-13",
     "libomp5-14",
     "libomp5-15",
     "libpolly-14-dev",
     "libunwind-13",
     "libunwind-13-dev",
     "libunwind-14",
     "libunwind-14-dev",
     "libunwind-15",
     "libunwind-15-dev",
     "lld-13",
     "lld-14",
     "lld-15",
     "lldb-13",
     "lldb-14",
     "lldb-15",
     "llvm-13",
     "llvm-13-dev",
     "llvm-13-doc",
     "llvm-13-examples",
     "llvm-13-linker-tools",
     "llvm-13-runtime",
     "llvm-13-tools",
     "llvm-14",
     "llvm-14-dev",
     "llvm-14-doc",
     "llvm-14-examples",
     "llvm-14-linker-tools",
     "llvm-14-runtime",
     "llvm-14-tools",
     "llvm-15",
     "llvm-15-dev",
     "llvm-15-doc",
     "llvm-15-examples",
     "llvm-15-linker-tools",
     "llvm-15-runtime",
     "llvm-15-tools",
     "mlir-13-tools",
     "mlir-14-tools",
     "mlir-15-tools",
     "python3-clang-13",
     "python3-clang-14",
     "python3-clang-15",
     "python3-lldb-13",
     "python3-lldb-14",
     "python3-lldb-15"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "12"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "clang-13",
     "clang-13-doc",
     "clang-13-examples",
     "clang-format-13",
     "clang-tidy-13",
     "clang-tools-13",
     "clangd-13",
     "libc++-13-dev",
     "libc++1-13",
     "libc++abi-13-dev",
     "libc++abi1-13",
     "libclang-13-dev",
     "libclang-common-13-dev",
     "libclang-cpp13",
     "libclang-cpp13-dev",
     "libclang1-13",
     "libclc-13",
     "libclc-13-dev",
     "libfuzzer-13-dev",
     "liblld-13",
     "liblld-13-dev",
     "liblldb-13",
     "liblldb-13-dev",
     "libllvm-13-ocaml-dev",
     "libllvm13",
     "libmlir-13",
     "libmlir-13-dev",
     "libomp-13-dev",
     "libomp-13-doc",
     "libomp5-13",
     "libunwind-13",
     "libunwind-13-dev",
     "lld-13",
     "lldb-13",
     "llvm-13",
     "llvm-13-dev",
     "llvm-13-doc",
     "llvm-13-examples",
     "llvm-13-linker-tools",
     "llvm-13-runtime",
     "llvm-13-tools",
     "mlir-13-tools",
     "python3-clang-13",
     "python3-lldb-13"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
