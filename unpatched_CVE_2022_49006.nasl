#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225798);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49006");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49006");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tracing: Free buffers when a used
    dynamic event is removed After 65536 dynamic events have been added and removed, the type field of the
    event then uses the first type number that is available (not currently used by other events). A type
    number is the identifier of the binary blobs in the tracing ring buffer (known as events) to map them to
    logic that can parse the binary blob. The issue is that if a dynamic event (like a kprobe event) is traced
    and is in the ring buffer, and then that event is removed (because it is dynamic, which means it can be
    created and destroyed), if another dynamic event is created that has the same number that new event's
    logic on parsing the binary blob will be used. To show how this can be an issue, the following can crash
    the kernel: # cd /sys/kernel/tracing # for i in `seq 65536`; do echo 'p:kprobes/foo do_sys_openat2
    $arg1:u32' > kprobe_events # done For every iteration of the above, the writing to the kprobe_events will
    remove the old event and create a new one (with the same format) and increase the type number to the next
    available on until the type number reaches over 65535 which is the max number for the 16 bit type. After
    it reaches that number, the logic to allocate a new number simply looks for the next available number.
    When an dynamic event is removed, that number is then available to be reused by the next dynamic event
    created. That is, once the above reaches the max number, the number assigned to the event in that loop
    will remain the same. Now that means deleting one dynamic event and created another will reuse the
    previous events type number. This is where bad things can happen. After the above loop finishes, the
    kprobes/foo event which reads the do_sys_openat2 function call's first parameter as an integer. # echo 1 >
    kprobes/foo/enable # cat /etc/passwd > /dev/null # cat trace cat-2211 [005] .... 2007.849603: foo:
    (do_sys_openat2+0x0/0x130) arg1=4294967196 cat-2211 [005] .... 2007.849620: foo:
    (do_sys_openat2+0x0/0x130) arg1=4294967196 cat-2211 [005] .... 2007.849838: foo:
    (do_sys_openat2+0x0/0x130) arg1=4294967196 cat-2211 [005] .... 2007.849880: foo:
    (do_sys_openat2+0x0/0x130) arg1=4294967196 # echo 0 > kprobes/foo/enable Now if we delete the kprobe and
    create a new one that reads a string: # echo 'p:kprobes/foo do_sys_openat2 +0($arg2):string' >
    kprobe_events And now we can the trace: # cat trace sendmail-1942 [002] ..... 530.136320: foo:
    (do_sys_openat2+0x0/0x240) arg1= cat-2046 [004] ..... 530.930817: foo: (do_sys_openat2+0x0/0x240)
    arg1=
    cat-2046 [004] ..... 530.930961: foo: (do_sys_openat2+0x0/0x240)
    arg1=
    cat-2046 [004] ..... 530.934278: foo: (do_sys_openat2+0x0/0x240)
    arg1=
    cat-2046 [004] ..... 530.934563: foo: (do_sys_openat2+0x0/0x240)
    arg1= ---truncated--- (CVE-2022-49006)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
