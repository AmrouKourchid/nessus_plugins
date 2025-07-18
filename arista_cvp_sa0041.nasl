#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138345);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/01");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479");
  script_bugtraq_id(108798, 108801, 108818);
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"Arista Networks CloudVision Portal Linux Kernel TCP Multiple DoS (SA0041)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks CloudVision Portal running on the remote device is affected by multiple denial of service (DoS) vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks CloudVision Portal running on the remote device is affected by the following denial of
service (DoS) vulnerabilities related to TCP networking in the Linux kernel, which can be exploited by a remote,
unauthenticated attacker:

  - SACK Panic. The TCP_SKB_CB(skb)->tcp_gso_segs value is subject to an integer overflow in the Linux
    kernel when handling TCP Selective Acknowledgments (SACKs). (CVE-2019-11477)

  - SACK Slowness.  The TCP retransmission queue implementation in tcp_fragment in the Linux kernel can be
    fragmented when handling certain TCP Selective Acknowledgment (SACK) sequences. (CVE-2019-11478)

  - The Linux kernel default MSS is hard-coded to 48 bytes. This allows a remote peer to fragment TCP resend
    queues significantly more than if a larger MSS were enforced. (CVE-2019-11479)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number. To retrieve version information this plugin requires the HTTP credentials of the web console.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/8066-security-advisory-41
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0073e92b");
  script_set_attribute(attribute:"solution", value:
"Apply the mitigation or upgrade to a fixed version as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11477");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:arista:cloudvision_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_cloudvision_portal_detect.nbin");
  script_require_keys("installed_sw/Arista CloudVision Portal", "Settings/ParanoidReport");

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:443);
app = 'Arista CloudVision Portal';

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { 'fixed_version':'2018.2.5', 'fixed_display':'2018.2.5, 2019.1.0, or later'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
