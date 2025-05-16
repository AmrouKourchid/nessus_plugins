#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K17403481.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(118635);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2018-8897");

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (K17403481)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A statement in the System Programming Guide of the Intel 64 and IA-32
Architectures Software Developer's Manual (SDM) was mishandled in the
development of some or all operating-system kernels, resulting in
unexpected behavior for #DB exceptions that are deferred by MOV SS or
POP SS, as demonstrated by (for example) privilege escalation in
Windows, macOS, some Xen configurations, or FreeBSD, or a Linux kernel
crash. The MOV to SS and POP SS instructions inhibit interrupts
(including NMIs), data breakpoints, and single step trap exceptions
until the instruction boundary following the next instruction (SDM
Vol. 3A; section 6.8.3). (The inhibited data breakpoints are those on
memory accessed by the MOV to SS or POP to SS instruction itself.)
Note that debug exceptions are not inhibited by the interrupt enable
(EFLAGS.IF) system flag (SDM Vol. 3A; section 2.3). If the instruction
following the MOV to SS or POP to SS instruction is an instruction
like SYSCALL, SYSENTER, INT 3, etc. that transfers control to the
operating system at CPL < 3, the debug exception is delivered after
the transfer to CPL < 3 is complete. OS kernels may not expect this
order of events and may therefore experience unexpected behavior when
it occurs. (CVE-2018-8897)

Impact

This vulnerability allows for a disruption of service.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K17403481");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K17403481.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

var sol = 'K17403481';
var vmatrix = {
  'AFM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'AM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'APM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'ASM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'AVR': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'DNS': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'GTM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'LC': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'LTM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'PEM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  },
  'WAM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.3.3','11.5.9'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
}
else
{
  var tested = bigip_get_tested_modules();
  var audit_extra = 'For BIG-IP module(s) ' + tested + ',';
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, 'running any of the affected modules');
}
