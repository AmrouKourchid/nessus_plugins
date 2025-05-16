#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000148479.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(210745);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/24");

  script_cve_id("CVE-2023-52881");

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (K000148479)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 16.1.6 / 17.1.2.2 / 17.5.0. It is, therefore,
affected by a vulnerability as referenced in the K000148479 advisory.

    In the Linux kernel, the following vulnerability has been resolved: tcp: do not accept ACK of bytes we
    never sent This patch is based on a detailed report and ideas from Yepeng Pan and Christian Rossow. ACK
    seq validation is currently following RFC 5961 5.2 guidelines: The ACK value is considered acceptable only
    if it is in the range of ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT). All incoming segments whose ACK
    value doesn't satisfy the above condition MUST be discarded and an ACK sent back. It needs to be noted
    that RFC 793 on page 72 (fifth check) says: If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be
    ignored. If the ACK acknowledges something not yet sent (SEG.ACK > SND.NXT) then send an ACK, drop the
    segment, and return. The ignored above implies that the processing of the incoming data segment
    continues, which means the ACK value is treated as acceptable. This mitigation makes the ACK check more
    stringent since any ACK < SND.UNA wouldn't be accepted, instead only ACKs that are in the range ((SND.UNA
    - MAX.SND.WND) <= SEG.ACK <= SND.NXT) get through. This can be refined for new (and possibly spoofed)
    flows, by not accepting ACK for bytes that were never sent. This greatly improves TCP security at a little
    cost. I added a Fixes: tag to make sure this patch will reach stable trees, even if the 'blamed' patch was
    adhering to the RFC. tp->bytes_acked was added in linux-4.2 Following packetdrill test (courtesy of Yepeng
    Pan) shows the issue at hand: 0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 +0 setsockopt(3, SOL_SOCKET,
    SO_REUSEADDR, [1], 4) = 0 +0 bind(3, ..., ...) = 0 +0 listen(3, 1024) = 0 // ---------------- Handshake
    ------------------- // // when window scale is set to 14 the window size can be extended to // 65535 *
    (2^14) = 1073725440. Linux would accept an ACK packet // with ack number in (Server_ISN+1-1073725440.
    Server_ISN+1) // ,though this ack number acknowledges some data never // sent by the server. +0 < S 0:0(0)
    win 65535 +0 > S. 0:0(0) ack 1 <...> +0 < . 1:1(0) ack 1 win 65535 +0 accept(3, ..., ...) = 4 // For the
    established connection, we send an ACK packet, // the ack packet uses ack number 1 - 1073725300 + 2^32, //
    where 2^32 is used to wrap around. // Note: we used 1073725300 instead of 1073725440 to avoid possible //
    edge cases. // 1 - 1073725300 + 2^32 = 3221241997 // Oops, old kernels happily accept this packet. +0 < .
    1:1001(1000) ack 3221241997 win 65535 // After the kernel fix the following will be replaced by a
    challenge ACK, // and prior malicious frame would be dropped. +0 > . 1:1(0) ack 1001(CVE-2023-52881)

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000148479");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K000148479.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52881");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_iapps_lx");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_irules_lx");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_ssl_orchestrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K000148479';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'APM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'ASM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'DNS': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'GTM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'LTM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'PEM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'PSM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'SSL-Orchestrator': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'WOM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'iAppsLX': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
    ],
  },
  'iRulesLX': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2','16.1.6'
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
