#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K32804955.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(142523);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2019-10639");

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (K32804955)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Linux kernel 4.x (starting from 4.1) and 5.x before 5.0.8 allows
Information Exposure (partial kernel address disclosure), leading to a
KASLR bypass. Specifically, it is possible to extract the KASLR kernel
image offset using the IP ID values the kernel produces for
connection-less protocols (e.g., UDP and ICMP). When such traffic is
sent to multiple destination IP addresses, it is possible to obtain
hash collisions (of indices to the counter array) and thereby obtain
the hashing key (via enumeration). This key contains enough bits from
a kernel address (of a static variable) so when the key is extracted
(via enumeration), the offset of the kernel image is exposed. This
attack can be carried out remotely, by the attacker forcing the target
device to send UDP or ICMP (or certain other) traffic to
attacker-controlled IP addresses. Forcing a server to send UDP traffic
is trivial if the server is a DNS server. ICMP traffic is trivial if
the server answers ICMP Echo requests (ping). For client targets, if
the target visits the attacker's web page, then WebRTC or gQUIC can be
used to force UDP traffic to attacker-controlled IP addresses. NOTE:
this attack against KASLR became viable in 4.1 because IP ID
generation was changed to have a dependency on an address associated
with a network namespace. (CVE-2019-10639)

Impact

This vulnerability can result in leaking information to a remote user
and potentially defeating KASLR.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K32804955");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K32804955.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var sol = 'K32804955';
var vmatrix = {
  'AFM': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'AM': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'APM': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'ASM': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'AVR': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'DNS': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'GTM': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'LC': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'LTM': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'PEM': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  },
  'WAM': {
    'affected': [
      '16.0.0','15.0.0-15.1.0','14.0.0-14.1.3','13.1.0-13.1.3'
    ],
    'unaffected': [
      '16.0.1','15.1.1','14.1.3.1','13.1.3.5'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
