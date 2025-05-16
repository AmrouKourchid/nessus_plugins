#TRUSTED 00ccde4a7e57e62de3ae4588863e632f16ada72c7c6ed2122e49e661d82faa43edf8e6f87d3705effab25897ef745833d982d4293dd35b72240356f89241374131a725adba1e5362edb357e9aa3c5c208e1bd813531611e37a23879f1c5a070017ef21e027782f111603ccbcc949bc963985cfbbffdb8f067b9a605d0824b3e656bfe3b2a05901d68fd646fcbf3e27705bc6cb1c35ed09a4955eaecce14d2dd3367eabca8554b3e7063f8cb5744d842fd8bd9f2d87489450aacdb6c128bd9035c24c655ad0a058d88e28e2886d2c71f0bd375f3a7c8c564a4d681b18d30150a40b13591aa6d269add11ca3aa04ba4de7c92d231411fe20fa2da64150af8a8ab91d5658e93c29b00229fe8976e89c1751c1b5e466508482771ccf72abaadb50bb39943ca1df75a432b551737b4e2427790d5b686980bc61f6a2d7ee570c371998d0d0c6f192e9ca97f857554876e3867ba23bdff148fd2e00610aff915754b9b4af3347e131ec23fec17a717fb1e7acf31143ff1abe85d632d1f319b80627a83cf2218b097569c06c5ce3d4979e8d05b93b7b8cd863cf5f337c913ea08e431513c729e7acc10dc7f2723d56d64761bfa630dbfdb2841d29fb7da2a8781f50d56d4500fcc586b570d2008687708de938be7300c5010acf3af8415f2c0014dbfff5b3bb512d8e7b93a1f02f08f010094b2fe832ea007c4518421b5fd0ac038a613e
#TRUST-RSA-SHA256 7befe3acbad9d8737491d3f49458e96671e1ef0999986c42811e583ebcfe1895eed89daee4e654fcb923c49f553f722ab1554fc9f0eb1ef1f41642029b9c6b1599b95e8f4bbad5dd9decf59b61ec2524966e1961b86222fa3505509890eeea1d654e3f3b006150ce33f95e81b3f853992e46c7b30955d11e90004f0a7b71645f954fab23dbe0b1113734e4cffaebc5cf24700722252dc0d5a03d6cadb6ca0e7e538e3c8931aa317d78e241f6d91721ab7b532dc1dcf07df5790e8ac23711f15d94b573e3f5864b4c7962fd001e31dc85b660f8ef5d1186733886cdfd7d3e0e12b0d71f2cb35182c0423181beffb1c46aaa630639b82f490c43f742c23dd20ea652bcb0d0dfff13abce4a47220bd0ad492d8d1c042404536929778a84ced0a57a5b0303187b9ee7af0ba4a35573d89f57d07dfbce789fd8e802074fce93d25d0ae50e730d1aa8d6658dc250545dcbd44f51a505196841a4a65b03eda5c89a904f3fd49cc48cc1b12159a06357fb8e3014e6ae79bd39cae5e00b86419962744aa1dcbeb149abfaecfe41433ac3a4e8a664bc8481666054a208870443a782d168bab2d49d78e9507ad095c6cf206ed40a44d7ce5b9261c60bdcdb839a20447634d174f6d2ddd038663b67940b2e7784996144c0082392a14dcba02eaeb77a7bb58b4c744cd7ae7bd17804e7ee4b23d557e8cef2055b447b31bb17fb4e2a821b47d3
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134303);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/25");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479");
  script_bugtraq_id(108798, 108801, 108818);
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"Arista Networks EOS Linux Kernel TCP Multiple DoS (SA0041)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by multiple denial of service (DoS) vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by the following denial of service (DoS)
vulnerabilities related to TCP networking in the Linux kernel, which can be exploited by a remote, unauthenticated
attacker:

  - SACK Panic. The TCP_SKB_CB(skb)->tcp_gso_segs value is subject to an integer overflow in the Linux
    kernel when handling TCP Selective Acknowledgments (SACKs). (CVE-2019-11477)

  - SACK Slowness.  The TCP retransmission queue implementation in tcp_fragment in the Linux kernel can be
    fragmented when handling certain TCP Selective Acknowledgment (SACK) sequences. (CVE-2019-11478)

  - The Linux kernel default MSS is hard-coded to 48 bytes. This allows a remote peer to fragment TCP resend
    queues significantly more than if a larger MSS were enforced. (CVE-2019-11479)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/8066-security-advisory-41
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0073e92b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.22.1F, 4.21.7M, 4.20.14M, 4.19.13M, 4.18.12M or later or 4.21.2.3F or
4.21.6.1.1F, or apply the patch from the vendor advisory.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('arista_eos_func.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit('Host/Arista-EOS/Version');
ext='SecurityAdvisory0041Hotfix.rpm 1.0.2/eng';
sha='7f19af46d5e520364039e4e4870a6906b233908b7ddeac6bb613bb956f797b64ede92d146d3824764502e1434d0f5f1c84db7a6c7723ac784b1db18d2b75f21a';

if(eos_extension_installed(ext:ext, sha:sha))
  audit(AUDIT_HOST_NOT, 'not vulnerable, as a relevant hotfix has been installed');

version = get_kb_item_or_exit('Host/Arista-EOS/Version');

vmatrix = make_array();
vmatrix['all'] = make_list('0.0<=4.17.99');
vmatrix['F']   =  make_list('4.22.0');
vmatrix['M']   =  make_list('4.21.0<=4.21.6',
                            '4.20.0<=4.20.13',
                            '4.19.0<=4.19.12',
                            '4.18.0<=4.18.11');

vmatrix['fix'] = '4.22.1F, 4.21.7M, 4.20.14M, 4.19.13M, 4.18.12M or later or 4.21.2.3F / 4.21.6.1.1F';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
