#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227324);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-4039");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-4039");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - **DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains that target AArch64 allows
    an attacker to exploit an existing buffer overflow in dynamically-sized local variables in your
    application without this being detected. This stack-protector failure only applies to C99-style
    dynamically-sized local variables or those created using alloca(). The stack-protector operates as
    intended for statically-sized local variables. The default behavior when the stack-protector detects an
    overflow is to terminate your application, resulting in controlled loss of availability. An attacker who
    can exploit a buffer overflow without triggering the stack-protector might be able to change program flow
    control to cause an uncontrolled loss of availability or to go further and affect confidentiality or
    integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by
    itself. (CVE-2023-4039)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4039");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/08");
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
     "cpp-10",
     "cpp-9",
     "g++-10",
     "g++-10-multilib",
     "g++-9",
     "g++-9-multilib",
     "gcc-10",
     "gcc-10-base",
     "gcc-10-hppa64-linux-gnu",
     "gcc-10-locales",
     "gcc-10-multilib",
     "gcc-10-plugin-dev",
     "gcc-10-test-results",
     "gcc-9",
     "gcc-9-base",
     "gcc-9-hppa64-linux-gnu",
     "gcc-9-locales",
     "gcc-9-multilib",
     "gcc-9-plugin-dev",
     "gcc-9-test-results",
     "gccgo-9",
     "gccgo-9-multilib",
     "gfortran-9",
     "gfortran-9-multilib",
     "gnat-9",
     "gobjc++-10",
     "gobjc++-10-multilib",
     "gobjc++-9",
     "gobjc++-9-multilib",
     "gobjc-10",
     "gobjc-10-multilib",
     "gobjc-9",
     "gobjc-9-multilib",
     "lib32asan5",
     "lib32asan6",
     "lib32atomic1",
     "lib32gcc-10-dev",
     "lib32gcc-9-dev",
     "lib32gcc-s1",
     "lib32gfortran-9-dev",
     "lib32go-9-dev",
     "lib32go14",
     "lib32gomp1",
     "lib32itm1",
     "lib32lsan0",
     "lib32objc-10-dev",
     "lib32objc-9-dev",
     "lib32objc4",
     "lib32quadmath0",
     "lib32stdc++-9-dev",
     "lib32stdc++6-9-dbg",
     "lib32ubsan1",
     "lib64asan5",
     "lib64asan6",
     "lib64atomic1",
     "lib64gcc-10-dev",
     "lib64gcc-9-dev",
     "lib64gcc-s1",
     "lib64gfortran-9-dev",
     "lib64go-9-dev",
     "lib64go14",
     "lib64gomp1",
     "lib64itm1",
     "lib64objc-10-dev",
     "lib64objc-9-dev",
     "lib64objc4",
     "lib64quadmath0",
     "lib64stdc++-9-dev",
     "lib64stdc++6-9-dbg",
     "lib64ubsan1",
     "libasan5",
     "libasan6",
     "libatomic1",
     "libcc1-0",
     "libgcc-10-dev",
     "libgcc-9-dev",
     "libgcc-s1",
     "libgcc-s2",
     "libgcc-s4",
     "libgccjit-10-dev",
     "libgccjit-10-doc",
     "libgccjit-9-dev",
     "libgccjit-9-doc",
     "libgccjit0",
     "libgfortran-9-dev",
     "libgo-9-dev",
     "libgo14",
     "libgomp1",
     "libitm1",
     "liblsan0",
     "libn32atomic1",
     "libn32gcc-10-dev",
     "libn32gcc-9-dev",
     "libn32gcc-s1",
     "libn32gfortran-9-dev",
     "libn32go-9-dev",
     "libn32go14",
     "libn32gomp1",
     "libn32objc-10-dev",
     "libn32objc-9-dev",
     "libn32objc4",
     "libn32stdc++-9-dev",
     "libn32stdc++6-9-dbg",
     "libobjc-10-dev",
     "libobjc-9-dev",
     "libobjc4",
     "libquadmath0",
     "libstdc++-9-dev",
     "libstdc++-9-doc",
     "libstdc++-9-pic",
     "libstdc++6-9-dbg",
     "libtsan0",
     "libubsan1",
     "libx32asan5",
     "libx32asan6",
     "libx32atomic1",
     "libx32gcc-10-dev",
     "libx32gcc-9-dev",
     "libx32gcc-s1",
     "libx32gfortran-9-dev",
     "libx32go-9-dev",
     "libx32go14",
     "libx32gomp1",
     "libx32itm1",
     "libx32lsan0",
     "libx32objc-10-dev",
     "libx32objc-9-dev",
     "libx32objc4",
     "libx32quadmath0",
     "libx32stdc++-9-dev",
     "libx32stdc++6-9-dbg",
     "libx32ubsan1"
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
  },
  {
   "product": {
    "name": [
     "cpp-11",
     "cpp-12",
     "g++-11",
     "g++-11-multilib",
     "g++-12",
     "g++-12-multilib",
     "gcc-11",
     "gcc-11-base",
     "gcc-11-hppa64-linux-gnu",
     "gcc-11-locales",
     "gcc-11-multilib",
     "gcc-11-plugin-dev",
     "gcc-11-test-results",
     "gcc-12",
     "gcc-12-base",
     "gcc-12-hppa64-linux-gnu",
     "gcc-12-locales",
     "gcc-12-multilib",
     "gcc-12-plugin-dev",
     "gcc-12-test-results",
     "gccgo-11",
     "gccgo-11-multilib",
     "gfortran-11",
     "gfortran-11-multilib",
     "gobjc++-11",
     "gobjc++-11-multilib",
     "gobjc++-12",
     "gobjc++-12-multilib",
     "gobjc-11",
     "gobjc-11-multilib",
     "gobjc-12",
     "gobjc-12-multilib",
     "lib32asan6",
     "lib32asan8",
     "lib32atomic1",
     "lib32gcc-11-dev",
     "lib32gcc-12-dev",
     "lib32gcc-s1",
     "lib32gfortran-11-dev",
     "lib32go-11-dev",
     "lib32go19",
     "lib32gomp1",
     "lib32itm1",
     "lib32lsan0",
     "lib32objc-11-dev",
     "lib32objc-12-dev",
     "lib32objc4",
     "lib32quadmath0",
     "lib32stdc++-11-dev",
     "lib32stdc++6-11-dbg",
     "lib32ubsan1",
     "lib64asan6",
     "lib64asan8",
     "lib64atomic1",
     "lib64gcc-11-dev",
     "lib64gcc-12-dev",
     "lib64gcc-s1",
     "lib64gfortran-11-dev",
     "lib64go-11-dev",
     "lib64go19",
     "lib64gomp1",
     "lib64itm1",
     "lib64objc-11-dev",
     "lib64objc-12-dev",
     "lib64objc4",
     "lib64quadmath0",
     "lib64stdc++-11-dev",
     "lib64stdc++6-11-dbg",
     "lib64ubsan1",
     "libasan6",
     "libasan8",
     "libatomic1",
     "libcc1-0",
     "libgcc-11-dev",
     "libgcc-12-dev",
     "libgcc-s1",
     "libgcc-s2",
     "libgcc-s4",
     "libgccjit-11-dev",
     "libgccjit-11-doc",
     "libgccjit-12-dev",
     "libgccjit-12-doc",
     "libgccjit0",
     "libgfortran-11-dev",
     "libgo-11-dev",
     "libgo19",
     "libgomp1",
     "libhwasan0",
     "libitm1",
     "liblsan0",
     "libn32atomic1",
     "libn32gcc-11-dev",
     "libn32gcc-12-dev",
     "libn32gcc-s1",
     "libn32gfortran-11-dev",
     "libn32go-11-dev",
     "libn32go19",
     "libn32gomp1",
     "libn32objc-11-dev",
     "libn32objc-12-dev",
     "libn32objc4",
     "libn32stdc++-11-dev",
     "libobjc-11-dev",
     "libobjc-12-dev",
     "libobjc4",
     "libquadmath0",
     "libstdc++-11-dev",
     "libstdc++-11-pic",
     "libstdc++6-11-dbg",
     "libtsan0",
     "libtsan2",
     "libubsan1",
     "libx32asan6",
     "libx32asan8",
     "libx32atomic1",
     "libx32gcc-11-dev",
     "libx32gcc-12-dev",
     "libx32gcc-s1",
     "libx32gfortran-11-dev",
     "libx32go-11-dev",
     "libx32go19",
     "libx32gomp1",
     "libx32itm1",
     "libx32lsan0",
     "libx32objc-11-dev",
     "libx32objc-12-dev",
     "libx32quadmath0",
     "libx32ubsan1"
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
