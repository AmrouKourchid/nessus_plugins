#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K51801290.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(184245);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id("CVE-2018-3640");

  script_name(english:"F5 Networks BIG-IP : RSRE Variant 3a vulnerability (K51801290)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K51801290 advisory.

    Systems with microprocessors utilizing speculative execution and that perform speculative reads of system
    registers may allow unauthorized disclosure of system parameters to an attacker with local user access via
    a side-channel analysis, aka Rogue System Register Read (RSRE), Variant 3a.(CVE-2018-3640)ImpactThere is
    no exposure on BIG-IP products by way of the data plane. All exposure is limited to the control plane,
    also known as the management plane. Additionally, on the control plane, the vulnerabilities are
    exploitable only by the following four authorized, authenticated account roles: Administrator, Resource
    Administrator, Manager, and iRules Manager. An attacker must be authorized to access the system in one of
    these roles to attempt to exploit the vulnerabilities.This vulnerability requires an attacker who can
    provide and run binary code of their choosing on the BIG-IP platform. As a result, these conditions
    severely restrict the exposure risk of BIG-IP products.Single-tenancy productsFor single-tenancy products,
    such as a standalone BIG-IP device, the risk is limited to a local, authorized user employing one of the
    vulnerabilities to read information from memory that they would not normally access, exceeding their
    privileges. A user may be able to access kernel-space memory, instead of their own user-space.Multi-
    tenancy environmentsFor multi-tenancy environments, such as cloud, Virtual Edition (VE), and Virtual
    Clustered Multiprocessing (vCMP), the same local kernel memory access risk applies as in single-tenancy
    environments. Additionally, the risk of attacks across guests exists, or attacks against the
    hypervisor/host. In cloud and VE environments, preventing these new attacks falls on the hypervisor/host
    platform, which is outside the scope of F5's ability to support or patch. Contact your cloud provider or
    hypervisor vendor to ensure their platforms or products are protected against Spectre Variants.For vCMP
    environments, while the Spectre Variant attacks offer a theoretical possibility of guest-to-guest or
    guest-to-host attacks, they are difficult to successfully conduct in the BIG-IP environment. The primary
    risk in the vCMP environment with Spectre variants only exists when vCMP guests are configured to use a
    single core. If the vCMP guests are configured to use two or more cores, the Spectre Variant
    vulnerabilities are eliminated.Vulnerability researchF5 is working with its hardware component vendors to
    determine the scope of vulnerabilities across its various generations of hardware platforms. All of the
    current information from F5's vendors is represented in this security advisory. F5 is working to obtain
    the remaining information from its vendors and will update the security advisory as F5 receives new
    information regarding its hardware platforms.F5 is also testing the fixes produced by the Linux community,
    and is conducting an extensive test campaign to characterize the impact of the fixes on system performance
    and stability to ensure a good experience for its customers. F5 does not want to rush the process and
    release fixes without a full understanding of potential issues. Given the limited exposure, the complexity
    of the fixes, and the potential issues, a detailed approach is warranted and rushing a fix could result in
    an impact to system stability or unacceptable performance costs. F5 will update this article with fixes as
    they become available.

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K51801290");
  script_set_attribute(attribute:"solution", value:
"The vendor has acknowledged the vulnerability, but no solution has been provided.
Refer to the vendor for remediation guidance.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3640");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/02");

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

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K51801290';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'AM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'AVR': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'LC': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
    ],
  },
  'WAM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.0.0-15.1.10','14.0.0-14.1.5','13.0.0-13.1.5','12.1.0-12.1.6','11.2.1-11.6.5'
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
