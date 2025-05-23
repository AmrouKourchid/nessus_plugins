#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K11186236.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(132554);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_cve_id("CVE-2019-6974");

  script_name(english:"F5 Networks BIG-IP : Linux kernel KVM subsystem vulnerability (K11186236)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"In the Linux kernel before 4.20.8, kvm_ioctl_create_device in
virt/kvm/kvm_main.c mishandles reference counting because of a race
condition, leading to a use-after-free. (CVE-2019-6974)

Impact

BIG-IP

An attacker may use this vulnerability to cause a vCMP guest to
crash,resulting in a denial-of-service orgain privileged access to the
vCMP hypervisor host system. This vulnerability affects only hardware
platforms that are vCMP-capable and are provisioned for vCMP. For a
list of vCMP capable hardware platforms, refer to K14088: vCMP host
and compatible guest version matrix.

BIG-IQ, Enterprise Manager, F5 iWorkflow, Traffix SDC

There is no impact; these F5 products are not affected by this
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K11186236");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K14088");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K11186236.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
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

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K11186236";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["AFM"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["AM"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["APM"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["ASM"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["AVR"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["GTM"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["LC"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["LTM"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["PEM"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("15.0.0-15.0.1","14.0.0-14.1.2","13.0.0-13.1.3");
vmatrix["WAM"]["unaffected"] = make_list("15.1.0","14.1.2.4","13.1.3.2");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_warning(port:0, extra:bigip_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
