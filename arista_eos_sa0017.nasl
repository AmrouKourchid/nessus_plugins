#TRUSTED 4effee22d0237b11f1fde0388047aa7c9611ea013541f4ef12d85f0a202a1e8a1da65105dbb81d8e85786261044e798fae41f4aad12e753cff7178d5f7f5f280188cd8787f8a19c6a203f0eb790bc840cc8f9c30583a606ba194e0e721fc3b6116b4ee024b04e1aabe005671f98d31747189513227224908332103ffeefa3c1eded6a5e880e1bdd10d975fad0e5d054f4f0e910e55e9810ba532e12b4901b0e7872922c60201b4a5183d032053f9768f268ce1896bc626fdd85b138bb739cbc0e517bc074d23bc9e4fd4899e041ccc04f4b7d76fbddfa8372d81cd67f7f38e3a03177c649f72848e8d59536abb3c5a081840e8924e1e88143a02f5a16af100af97c8189e5655efb5f705a6349d13d53a40b960b4db1035c1808aba3b0c23dcf1fdf02e5ea8eaf0da70ac9813f5c0df766211f73154a703a7ccf75a45791db6ec62eab61f7dcdaadcbb6fcf153f7d94aa96b618b563cf03d806fdb9fea15194a4d31637fd576af559c41471a9ca2620679ddbebffdadd61096d6c94e05a50f3aefa92bc0df9a2dd6e0980e2b55e539867c6c67a845af3dd4c464839cde68f28c63d2769258df280a9832cc29505bf184ad41c977b574156b9dd6e8eaac214813947090503a2517d741aa991ed63f14ace1701a6c1171b47c2a00a678ad530fe188dd2154522f233bb5805d068ded5954e4f96d9e3a31cd3a86ac595b1fa0a22df
#TRUST-RSA-SHA256 a5a3012cea39cc6e61d3d42dc659d1296a75debc0472593ec4d4a2c0ecc199eb11a8a66d4f9f5848a77d0fef9ee8b1f3f24fd3b44428f4c5bd33a6e196b1e7ac128eb23dc1d5a166bd095cd3958ca654e01c666d624cf3c5cf0dae25e1a24ab9c172ec37c1234485511a6b62618068f85b017129fcd5b1ee1990cc04aca4f5be2f05038e5b484a84e28a8f83d16674e98e4d067250bfa15cf29fdffe943a70906381c691804e28f363d2637babb83d63f520200ad0dc6c7d02e8fdba76af050ab4f8efc910e89651b395b5839d2dd744609ab320a14af0a6b0ac9d87c66b5b6b7f409cc80d3bf6ef4f8e360c3aa6a9ece5206b90ed51cf92ddeefba225d076843ca7614a4d0e61961ff5e5e2a427515905f927733f08c80ec07c1f43f024d98a9116d431b2de5899e312ad9b9c4a4142a818b1fdc81fc2c356d3f9385489fd01d4d1f9eeb932b6eca6d66aacdf992b270d177fc5be12c977583ffdf599f1fd00230c44e56f23e89d3828faf7d79a58a233303841bee8188facca79bd2bf059d4f151e315fe361480b9aa6cab6e22de8a84b34e023e12ccd733f14cc985ef1a465493f8e95ce9dfce982bca4e0a5ffe28db9ab3bd9931aecb3e94e2664902ee5f99034736766e22268cbc4777eb7bcd1bb2e452e919e250bd9b8e50d177baa7aadb0af27b643cefd76c8e21f619238e38ffc7015056c2a6deb4c43001a9427ce6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107059);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2015-7547");
  script_bugtraq_id(83265);
  script_xref(name:"CERT", value:"457759");
  script_xref(name:"EDB-ID", value:"39454");
  script_xref(name:"EDB-ID", value:"40339");

  script_name(english:"Arista Networks EOS libresolv Overflow RCE (SA0017)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple stack-based buffer overflow conditions in the GNU
libresolv library, specifically within the send_dg() and send_vc()
functions, when handling DNS responses that trigger a call to the
getaddrinfo() function with the AF_UNSPEC or AF_INET6 address family.
An unauthenticated, remote attacker can exploit these issues, via a
specially crafted DNS response, to cause a denial of service condition
or the execution of arbitrary code.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1255-security-advisory-17
  script_set_attribute( attribute:"see_also", value:"http://www.nessus.org/u?050a280a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.13.15M / 4.14.12M / 4.15.5M
or later. Alternatively, apply the patch or recommended mitigation
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7547");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version");

  exit(0);
}


include("arista_eos_func.inc");

version = get_kb_item_or_exit("Host/Arista-EOS/Version");
ext1="2.6.0/2980299.gamiltonsecAdvisory0017Patch.63";
sha1="16948241511ccf7044a8e1eeef4e55d2181194296ea02e22f2bd6df69a3f25386bf2938f3086f67a148d84d62ede10fc530fbbbd27a58bb49d4c642ecc675690";
ext2="glibc-common.i686.rpm 2.13/4Ar";
sha2="ccdf8ad84ac1a7985d89b026a6a311533a0f028c4a80c9a8fafa9b1ac4386fe169adb15145faea2e8c8f8cc8e9152f42150c9bd7df63b4dbd4612641d9aabded";

if(eos_extension_installed(ext:ext1, sha:sha1) || eos_extension_installed(ext:ext2, sha:sha2)) 
  exit(0, "The Arista device is not vulnerable, as a relevant hotfix has been installed.");

vmatrix = make_array();
vmatrix["all"] =  make_list("0.0<=4.11.99");
vmatrix["F"] =    make_list("4.13.1.1<=4.13.6",
                            "4.14.0<=4.14.5",
                            "4.15.0<=4.15.4");

vmatrix["M"] =    make_list("4.13.7<=4.13.14",
                            "4.14.6<=4.14.11");

vmatrix["misc"] = make_list("4.12.5.2",
                            "4.12.6.1",
                            "4.12.7.1",
                            "4.12.8", 
                            "4.12.8.1", 
                            "4.12.9", 
                            "4.12.10",
                            "4.12.11",
                            "4.14.5FX",
                            "4.14.5FX.1",
                            "4.14.5FX.2",
                            "4.14.5FX.3",
                            "4.14.5FX.4",
                            "4.14.5.1F-SSU",
                            "4.15.0FX",
                            "4.15.0FXA",
                            "4.15.0FX1",
                            "4.15.1FXB1",
                            "4.15.1FXB",
                            "4.15.1FX-7060X",
                            "4.15.1FX-7260QX",
                            "4.15.3FX-7050X-72Q",
                            "4.15.3FX-7060X.1",
                            "4.15.3FX-7500E3",
                            "4.15.3FX-7500E3.3",
                            "4.15.4FX-7500E3");
vmatrix["fix"] = "Apply one of the vendor supplied patches or upgrade to EOS 4.15.5M /4.14.12M / 4.13.15M or later";

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
