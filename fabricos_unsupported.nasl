#TRUSTED a9cdd33fda8e0317d64df63bdddd55826640ecf6c123edec3d9cb9339996bdadaa92cd53737df216a86e2548da445da1cec42773be815ab218bf8c3c2d56fd6af38bb38bac0db059901fbe01f69967378c22cd6e0ac2ea7022dbeaba949edddb48ba698f76b038388a60d0327a8532ae68147da78c7312be3f690ca86b50bf913d85c723c801b0f275dd8f5fc5042ce99011cd562fe7a399fa017077c77d323bc888ade6b66b8cf875a59140a44287b1dd604a8bd8a20bf4b5f06af23aa5a247568e1e104cc5b56cb654ff1a05d59cdcf91ac8a2d7c819e5ac2bdc6a7945aead02f1a121c70ba99c1fd353520228b8c783d6879876b020751a8e2fa9211c5f01453c5b93e9223c3a8354612b0ff7c17f6b95ba69f4194b6466eab6a41667f64431c4e58e7109d5adf468c02cffecc3208d629f20e046d58fcec46fee076a1351f614994e5221d877916793fde8ef6cfa287e687603d28b2ad4085860ad52a46110617d5196062dd51228bd9ff7fc9f0b234836c152f69bef8ff03ad247315946d9347932ed7a3ce245e3d0cbc66cdbddb716abfb648419690363e0c4dc18690386d604191da91e95b75311524c0a1f771371a344cbe978285f64c837c59e17db770c08cdebdf001d262a24dc56c624c9816b912a33a9325ead42ef17e650e260280e5b3f026f9433b324eba27b6dc0b3159f929ac77a2011f30dfda890233840
#TRUST-RSA-SHA256 4aec1d9a7fe1b5a734ae68ceb16ac7ddcf53f2eaecdd73629ad6a98f01a07bb94ab1172afc1a27a948fab4058945a4688b20dbbb4a810891d50717ec04eda29937695a72e17d677a47545401829ddb1bc6499abe03bde822fd23018b2a0b9cdcb317bb29308f54598fd85dfa2899f8839c4a9ecd9e378b95884f22bb7f6a72674f79c5210f6d55a65eff120241bb64e8bb1f6e48153f3dbb9e632ea1fb45d8154f543c8ddc3d660a5f4a89ee830a5a9b206547a7b7ec70faa8d0eb4578029196ce6ad3bcb964d4514268a34509ca85a8da691ecfb8131f535ecfec3321fdc510ba6a4c1c9537c88777799ccc1825015e82a0f7eab6132104a16b72718b5105fa59330b01c338abdc48965f06bf5466021367374fcc5b37bc46f7be1f5dfeef5d8ae4d41c1997be79a8603dd0a9da698db524e78f353dbf1aa09c822ceac7761b3512a6890a1566ae2218ae6fa90a3f54729641727282dc43eec7399e5da80894f2603ec49684674330b3baee9d75804c2ba0cc9b20850ba9055f67283c747155effbd5fd7c7a8e22f2379b6ea8297996fdfb8959f4d488c6997cc82a722cc7351f1abcc673df25c90c407f6f0e77daabe1c9f5f5e25112bbeea7cd5a124e848176916c130ff231c3528d3a29e69a96be80e0a42b4e180d41ecfac5b511a3e01feb4e0a8d6e496029061367b975471e4b5247cd7e19b8e0b55e2b2e10b19e431f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73598);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/05");

  script_xref(name:"IAVA", value:"0001-A-0607");

  script_name(english:"Unsupported Brocade Fabric OS");
  script_summary(english:"Checks if a version of Fabric OS is unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an obsolete operating system.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Fabric OS on the remote
host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.brocade.com/en/support/product-end-of-life.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Fabric OS that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:brocade:fabric_os");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Host/OS");

  exit(0);
}

include("snmp_func.inc");

var ver = NULL;

var os = get_kb_item_or_exit('Host/OS');

var match = pregmatch(string:os, pattern:'Fabric OS ([0-9a-zA-Z._-]+)$');

var community, port, soc, txt;

if (match)
{
  ver = match[1];
}

# SNMP
else if ("Brocade Switch" >< os)
{
  community = get_kb_item("SNMP/community");
  if (community)
  {
    port = get_kb_item("SNMP/port");
    if (!port) port = 161;
    if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

    soc = open_sock_udp(port);
    if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

    # Get version
    txt = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.1588.2.1.1.1.1.6.0");
    if (txt) ver = txt;
    else audit(AUDIT_UNKNOWN_APP_VER, "Fabric OS");
  }
}

if (isnull(ver)) audit(AUDIT_OS_NOT, "Fabric OS");

var latest = '9.2.1a';
var eoa_date = NULL;
var eoa_url = NULL;

# 7.1.x
if (
  ver =~ "^7\.1(\.|$)"
)
{
  eoa_date = "2015-04-15";
  # http://www.brocade.com/content/brocade/en/backend-content/pdf-page.html?/content/dam/common/documents/content-types/end-of-life-notice/brocade-fos-7.1.x-eoa-notice.pdf
  eoa_url = "http://www.nessus.org/u?ca91d510";
}

# 5.1.x - 5.3.x
else if (
  ver =~ "^5\.[1-3](\.|$)"
)
{
  eoa_date = "2009-02-04";
  # http://community.brocade.com/dtscp75322/attachments/dtscp75322/fibre/1316/2/FOS+5.3.x+EOA+Notice+v2.0.pdf
  eoa_url  = "http://www.nessus.org/u?e6145511";
}

# 2.6.2 and earlier
else if (ver =~ "^2\.[0-6]([^0-9]|$)")
{
  eoa_date = "2008-06-19";
  # https://web.archive.org/web/20150505044358/http://www.brocade.com/downloads/documents/end_of_availability_notice/FOS%202%206%202%20EOL%20v1.0.pdf
  eoa_url  = "http://www.nessus.org/u?137106c3";
}

# 3.x / 5.0.x
else if (
  ver =~ "^3\." ||
  ver =~ "^5\.0(\.|$)"
)
{
  eoa_date = "2008-05-01";
  # https://web.archive.org/web/20081125080318/http://www.brocade.com/downloads/documents/end_of_availability_notice/FOS%203%20x%205%200%20x%20and%20SFOS%20EOL%20v0%204%20_103007_.pdf
  eoa_url  = "http://www.nessus.org/u?2a46cb3b";
}

# 4.2.x - 4.4.x
else if (
  ver =~ "^4\.[2-4]([^0-9]|$)"
)
{
  eoa_date = "2007-03-31";
  # https://web.archive.org/web/20150505021442/http://www.brocade.com/downloads/documents/end_of_availability_notice/3_1_X4_4_X_7_3_XEOL052306.pdf
  eoa_url  = "http://www.nessus.org/u?3fc9f0cb";
}

# 4.1.x - 4.2.0x
else if (
  ver =~ "^4\.1([^0-9]|$)" ||
  ver =~ "^4\.2\.0([^0-9]|$)"
)
{
  eoa_date = "2005-12-31";
  # https://web.archive.org/web/20081203053619/http://www.brocade.com/downloads/documents/end_of_availability_notice/2_6_13_1_24_2_0EOLExtension.pdf
  eoa_url  = "http://www.nessus.org/u?8f7d93bb";
}

# 4.0.1x - 4.0.2x
else if (
  ver =~ "^4\.0\.[12]([^0-9]|$)"
)
{
  eoa_date = "2004-08-31";
  # https://web.archive.org/web/20150505030101/http://www.brocade.com/downloads/documents/end_of_availability_notice/2_6_03_0_24_0_2EOLrev3.pdf
  eoa_url  = "http://www.nessus.org/u?0a22d9c2";
}

# 4.0.0x
else if (ver =~ "^4\.0\.0([^0-9]|$)")
{
  eoa_date = "2004-02-29";
  # https://web.archive.org/web/20150505045910/http://www.brocade.com/downloads/documents/end_of_availability_notice/3_0_04_0_0EOL082103.pdf
  eoa_url  = "http://www.nessus.org/u?abb3b15d";
}

# 6.x.x
else if (ver =~ "6\.[0-9]\.[0-9]([^0-9]|$)")
{
  eoa_date = "2014-07-23";
  eoa_url = "https://docs.broadcom.com/doc/FOS-EOA-OT";
}

# 7.0.x
else if (ver =~ "7\.0\.[0-9]([^0-9]|$)")
{
  eoa_date = "2014-09-27";
  eoa_url = "https://docs.broadcom.com/doc/FOS-EOA-OT";
}

# 7.1.x
else if (ver =~ "7\.1\.[0-9]([^0-9]|$)")
{
  eoa_date = "2015-10-15";
  eoa_url = "https://docs.broadcom.com/doc/FOS-EOA-OT";
}

# 7.2.x
else if (ver =~ "7\.2\.[0-9]([^0-9]|$)")
{
  eoa_date = "2016-03-16";
  eoa_url = "https://docs.broadcom.com/doc/FOS-EOA-OT";
}

# 7.3.x
else if (ver =~ "7\.3\.[0-9]([^0-9]|$)")
{
  eoa_date = "2017-03-14";
  eoa_url = "https://docs.broadcom.com/doc/FOS-EOA-OT";
}

# 7.4.x
else if (ver =~ "7\.4\.[0-9]([^0-9]|$)")
{
  eoa_date = "2019-03-30";
  eoa_url = "https://docs.broadcom.com/doc/FOS-EOA-OT";
}

# 8.0.x
else if (ver =~ "8\.0\.[0-9]([^0-9]|$)")
{
  eoa_date = "2020-07-31";
  eoa_url = "https://docs.broadcom.com/doc/FOS-EOA-OT";
}

# 8.1.x
else if (ver =~ "8\.1\.[0-9]([^0-9]|$)")
{
  eoa_date = "2022-03-15";
  eoa_url = "https://docs.broadcom.com/doc/FOS-EOA-OT";
}

# 8.2.x currently LSA
# else if (ver =~ "8\.2\.[0-9]([^0-9]|$)")
# {
#   eoa_date = "2023-07-28";
#   eoa_url = "https://docs.broadcom.com/doc/FOS-EOA-OT";
# }

if (isnull(eoa_date)) exit(0, 'Fabric OS ' + ver + ' is still supported.');

register_unsupported_product(
  product_name:'Brocade Fabric OS',
  cpe_class:CPE_CLASS_OS,
  version:ver,
  cpe_base:"brocade:fabric_os"
);

if (report_verbosity > 0)
{
  report =
    '\n  Installed Fabric OS version : ' + ver +
    '\n  EOA date                    : ' + eoa_date +
    '\n  EOA URL                     : ' + eoa_url  +
    '\n  Latest Fabric OS version    : ' + latest + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
