#TRUSTED 32f37c4399f0d202a2dbb3e296860bff825b29be2ae38fa27b6f5972a12a181de94d72bb4246c2b846317e0687ae106978b5d4bf69d409bcbe42a0904e06ea6ff41623fd4dab85fd1dcb2f878b67a4a8797c51f4af0f8bede89437b2e01068004a77fc336109e98c9370f4b5e38a22798896acae38c805e7987d9870dfb077997db5251cf7184f285f6ee7ceb038be9399ac2427646eeaca5e4b698a8443625e74b0610b80165cef72608843070848da816b761f8431301db8c76bbbe912c94879eee8f7a3022b2d03aa5037e929ec02b6247911543c76483fb1f0f403e93149e3fb678eb9802f68e76de1b487c2fdd73bb6ee730ada35f85636a82f06a65bbb55c6a4854ff21dd8ebc062dd9d165df79faec09fd6d0884dd7fce7c6e830f7b79037f7907684c4b101cba737e6ae9bd4ebf022b03ab20291409d2f2381edf09c2f02f6395d4a929697ccf40c4b2fd606bf37222cc3f19b17e6e74407f8f65cd262624da20782c945a5897fde95061b104b00e5c82b9142139237bd89ce34def769baf7332ddde8353f050ac4879fc7cf0c7b691955df67e1f576cacc6e878ebf159c830b7c5c144d04da8bc4c3fcc992c99eda73a6602c371fa0ad97fd62e57ae1c58b0ea4ecef596f5186af1d44a5b81ebcb41aa8447c286a56a0a2c321bf0188ae1c7e992435f64837ef91c061f8d45981512251c98dd4c34c769a43f1cb72
#TRUST-RSA-SHA256 23c979b8391f36a4f4d6bb899ea4ee1e2050481f772a6352024caf369c317680006520351dab589dcfd237f92d26731aa6a2ef3fbb5012309c8ff8bbf500b3a38b1179b9ff1fd98511e2f42a6671c9d443f9ac9189a1a82dc6c9041ff94d7a99848588887df8a3a454d4edf48521880548fa5f2588dd56c117c219465b9855deb65184801ce469e1d74215e6f17256aefeb613935bbe417c74222091cd2fbb751d2215f83867de6270b6a3f1161252bec70632442b4a2b64e9d78f7490eab074c08529e462b160a00a193eeb2e2830410bbb8a9d4952ae2adce488ddbc3065d9d33361d32423602e33567b4ca8f1302e223c546b7fa2133f06af5a97a6060961b67b713b1ede315f1f84b407d8227ea937ae2f9e132d429beaac09a20daef09d5028c1b6e2bf9134ebba0158d61bc68ee74c7d3032dfdf1099769925a46feb31b74cc4ccbb0b41f00f873eb25172079d242d802d545735e21d8c69ca53a8f276777dd07cdeaf8d67e66c123a186f471479374aad150670b6a63562a2251a3eb24aa0abe2b0abf6f1d263e0267fcf81dd28c08cc124ce9c915b78c667094e2160c5911266843439d619909392d620614623af57641f472035c5b9851aac666b28e38802c296683a3c6746393f80ef6495f8a3f835a1b1f6393fe855be6d5a69a4b62488d972f6f379d098e17264caade90a14cdf5ef29f09be1ff65ff086f394e

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101166);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"RHEL / CentOS 6.x (64-bit) Malicious Kernel Module Detection (OutlawCountry)");
  script_summary(english:"Attempts to detect OutlawCountry kernel module install.");

  script_set_attribute(attribute:"synopsis", value:
"A malicious kernel module is potentially installed on the remote Linux
host.");
  script_set_attribute(attribute:"description", value:
"According to diagnostic indicators, the remote Red Hat Enterprise
Linux or CentOS host may have a malicious kernel module known as
OutlawCountry installed. OutlawCountry creates a hidden netfilter
table that allows an authenticated attacker to covertly override
existing netfilter/iptables firewall rules.

Note that only RHEL and CentOS 6.x operating systems running kernel
version 2.6.32 (64-bit) are reportedly affected. OutlawCountry was
disclosed on 2017/06/30 by WikiLeaks as part of their ongoing
'Vault 7' series of leaks.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/solutions/3099221");
  script_set_attribute(attribute:"solution", value:
"Refer to the referenced Red Hat solution article.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

redhat_release = get_kb_item("Host/RedHat/release");
centos_release = get_kb_item("Host/CentOS/release");

if(isnull(redhat_release) && isnull(centos_release))
  audit(AUDIT_OS_NOT, "Red Hat Enterprise Linux / CentOS");

combined = redhat_release + centos_release;
arch = get_kb_item("Host/cpu");

if("64" >!< arch || "release 6" >!< combined ||  combined !~ "(Red Hat Enterprise Linux|CentOS)")
  audit(AUDIT_OS_NOT, "64 bit Red Hat Enterprise Linux / CentOS 6.x");

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

res1 = info_send_cmd(cmd:"iptables -t dpxvke8h18 -L -nv");
res2 = info_send_cmd(cmd:"lsmod");

if (info_t == INFO_SSH) ssh_close_connection();

vuln = FALSE;
if("Chain PREROUTING" >< res1 && "nf_table" >< res2)
  vuln = TRUE;

if(!vuln)
  exit(0, "The remote host does not appear to be affected.");

report = 
  '\nBased on the output of "iptables -t dpxvke8h18 -L -nv", the host is' +
  '\nrunning a hidden filter table that may indicate a malicious kernel' +
  '\nmodule is installed (according to unverifiable reports from WikiLeaks' +
  '\nand the media).' +
  '\n' +
  '\nCommand output :\n\n' + res1 + '\n';

security_hole(port:0, extra:report);

