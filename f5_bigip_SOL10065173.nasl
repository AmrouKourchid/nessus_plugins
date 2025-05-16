#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K10065173.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(122432);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id("CVE-2019-6593");
  script_bugtraq_id(70574);

  script_name(english:"F5 Networks BIG-IP : TMM TLS virtual server vulnerability (K10065173)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A BIG-IP virtual server configured with a Client SSL profile may be
vulnerable to a chosen ciphertext attack against CBC ciphers. When
exploited, this may result in plaintext recovery of encrypted messages
through a man-in-the-middle (MITM) attack, despite the attacker not
having gained access to the server's private key itself.
(CVE-2019-6593 also known as Zombie POODLE and GOLDENDOODLE)

Impact

Exploiting this vulnerability to perform plaintext recovery of
encrypted data may reveal session authentication cookies similar to
CVE-2014-3566 (POODLE). Only TLS sessions established using CBC mode
encryption are vulnerable to this attack.

To exploit this vulnerability, the attacker must have a privileged
network position to intercept controlled HTTPS requests, which are
generally initiated via JavaScript originating in any browser context.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K10065173");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K10065173.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6593");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/26");

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

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K10065173';
var vmatrix = {
  'AFM': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'AM': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'APM': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'ASM': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'AVR': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'DNS': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'GTM': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'LC': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'LTM': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'PEM': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
    ],
  },
  'WAM': {
    'affected': [
      '12.1.0','11.6.1','11.5.1-11.5.4'
    ],
    'unaffected': [
      '12.1.1','12.1.0 HF1','11.6.2','11.6.1 HF1','11.5.5','11.5.4 HF2'
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
