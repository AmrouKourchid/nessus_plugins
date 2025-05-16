#TRUSTED 3324579bf207f0f0a0b9223ef8df2f1c5ff9436261adb494a5df132fa17354c0dedaa0287b8b1e2981a753bea7d97a427ea05d7caa25a09183a9e40196587f53922fa539f2846c4fc4ce2eef59b4cfb6cac715eeeacfa65de2f4bf80157692f0495455cfb82386b1871a4f935e0eb6dc041d90b98b993e1903575302333944fe89313a26cfdcc740a9eb989a2f094408a9ecc47a55642903bc42c1b2031d884914acc6afe9153e06d0bd7466a25f8161ba4615c109ca311b8439bf24c193814fed6b2d12ba5221ad9e51e5ed248799d8aa3014f3a31d471127a289389b590e35277ebae13f2752c2a1b2789760c14775dc2b66a2d1974bea0f9feb2e92149b097548103f80f7c0ee3cd08f7429eab65fd1ceeb87a12052a6c00cf867834e2dfcb201dd87d852f35eea7d131001d9e7750c9dad4e135a76cbafb7df477d5629378cbc5f61c0cd10e659c7a7ed1c3bb2459d39c280769919731777f568f00c0544864de24ea58ce59cb72eef1056ebc821fe3049dbf6b5b6bc8600c623083751eebb41808949b18fd73ca2dfdd6d94000be5716c2107c24d307f961940f44fa3fac80ea73e096efcd5b2d3a163450b66cd6a207861d27109c1d3451ad25b20640c9f9ae7333298717bbfe94ea258a113ae2149b1f52b17a68f449829e5741fef1c353f708226e7de371b00c00c1cad31bcbb652093bbde099a16257aaf66787f6f
#TRUST-RSA-SHA256 1c480fc99f3599789ac1bf718cd3946ac7c2f4dd5229428e1b7800555b8d07766b7136d296ac08a820e9517e7be9084c089a7f0a4dea5a3163da311ead747d81d19e2d1f8c4c19de39387875862b3a87c1d7b158ebaf529b50ebe4eb762c02710445a5cc66348020fa4aede2c6b8f3bea67f95f13bb6eeb76a5372140016d89c540aa33a134a2295d28a14b2fdb4211bc679bdb8c30ea30b6390213082157b009fc4827e9f24a514c6b29f9f77bda1cc32b6b16a0a6ef7c3eca9e0684b5a6a6c3ea6185273d46ca507aa5ea3c90dfb059da96fcda1327e866d7bc86cca9c453d68ec2654c4ef2e89e0dd73a6ca325bcb55e62f2f71d4f3e126d7b0eb400c1961cd7e094f447465de77c05acb8cca5e4a8552fb6b9a2375139cea364b473dee0921b2d70aae603de3b88c6c8a31282df02c89a8b6eb8c817060d74b6a4a6e18cb89b88f7a3914ea88fc63444c40b43b422d7fcd58ce9b6034716233fd4514314575bb616c70893ea1b191141a8f92cb80ca88eb37dcc0608fae69eca19895b5b56906d5cee3d1ffcf08eec40e860fb5191a57fb12de82b271c71a4864dd538b03a810fae2173848753cd944fac43546946ba2dcf2d83e93fc2cc9e453f2b9241d5f8d6905ecd08fe4bc8fc8f6154581379a19dadc0b8250a9a12d1aab239964b7b79d3187a9005810d663cdd792c6da2baab47b2711932f118b7dc364f2cb06ed
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107060);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2015-3197", "CVE-2016-0703", "CVE-2016-0800");
  script_bugtraq_id(82237, 83733, 83743);
  script_xref(name:"CERT", value:"257823");
  script_xref(name:"CERT", value:"583776");

  script_name(english:"Arista Networks EOS Multiple Vulnerabilities (SA0018) (DROWN)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple vulnerabilities in the included OpenSSL library :

  - A cipher algorithm downgrade vulnerability exists due to
    a flaw that is triggered when handling cipher
    negotiation. A remote attacker can exploit this to
    negotiate SSLv2 ciphers and complete SSLv2 handshakes
    even if all SSLv2 ciphers have been disabled on the
    server. Note that this vulnerability only exists if the
    SSL_OP_NO_SSLv2 option has not been disabled.
    (CVE-2015-3197)

  - A flaw exists in the SSLv2 implementation,
    specifically in the get_client_master_key() function
    within file s2_srvr.c, due to accepting a nonzero
    CLIENT-MASTER-KEY CLEAR-KEY-LENGTH value for an
    arbitrary cipher. A man-in-the-middle attacker can
    exploit this to determine the MASTER-KEY value and
    decrypt TLS ciphertext by leveraging a Bleichenbacher
    RSA padding oracle. (CVE-2016-0703)

  - A flaw exists that allows a cross-protocol
    Bleichenbacher padding oracle attack known as DROWN
    (Decrypting RSA with Obsolete and Weakened eNcryption).
    This vulnerability exists due to a flaw in the Secure
    Sockets Layer Version 2 (SSLv2) implementation, and it
    allows captured TLS traffic to be decrypted. A
    man-in-the-middle attacker can exploit this to decrypt
    the TSL connection by utilizing previously captured
    traffic and weak cryptography along with a series of
    specially crafted connections to an SSLv2 server that
    uses the same private key. (CVE-2016-0800)

Note that these issues occur only when CloudVision eXchange (CVX) is
deployed as a virtual appliance and runs an EOS image. Therefore, only
CVX features leveraging SSLv2 in the EOS releases are vulnerable.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1260-security-advisory-18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4b2cf3");
  script_set_attribute(attribute:"see_also", value:"https://www.drownattack.com/drown-attack-paper.pdf");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.15.5M. Alternatively, apply
the recommended mitigations referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0800");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/07");
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

vmatrix = make_array();
vmatrix["misc"] = make_list("4.15.0F",
                            "4.15.0FX",
                            "4.15.0FXA",
                            "4.15.0FX1",
                            "4.15.1F",
                            "4.15.1FXB.1",
                            "4.15.1FXB",
                            "4.15.1FX-7060X",
                            "4.15.1FX-7260QX",
                            "4.15.2F",
                            "4.15.3F",
                            "4.15.3FX-7050X-72Q",
                            "4.15.3FX-7060X.1",
                            "4.15.3FX-7500E3",
                            "4.15.3FX-7500E3.3",
                            "4.15.4F",
                            "4.15.4FX-7500E3");
vmatrix["fix"] = "4.15.5M";

is_cvx = get_cvx();
if(!is_cvx) audit(AUDIT_HOST_NOT, "running cloud vision exchange");

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
