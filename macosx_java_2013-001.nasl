#TRUSTED 26e49091a12a6c6253745cea48f676cc0adc918cba6998911ae5384db3bbb0f92584333efd41a7fb058ce61b2837e9ffdb8bfac5abf6beb0668fe95ebdbb0218389eda419fe0e17d7f29dcb7ffca79234a3cab7c42235427a020a0e55469872f1053b19b08ea8f318543b41cc5524f9c85d539417c98229235007721163a6774014813af383583fb2ab451af3b8ab9920998aad302bb06c81747248a579294b53c3fda39c2abf4db8d95891532c4aab0991006a60392ba97abefab784c55b5f9f855af008764dbf453428036a47675df663d220f398d5531369ee428f2fa9abc0cf4230ce8fc375e3838d806fad9be8a1148fa8b4543e17d40408184453d8c570c4745f97c3baef6f471598d1332188013620430b7af9fcb0c0fb2680f38c7579c82d11c825772cdb157307fd8dbcae3f662ea4dd84420c3c16e49f80fe96f9343eefbf4b25e9f0ab4115f1af76e18f0ab8d9798ae49e3a1be20bc636ccbf4ac7aefc5d509dbe6ba8adef3e7e8639a1381f43f8c9425b91aefaf20a44a3515e11a709a6ed188d8ce83782b264eed1d394ced21c4e4ed133165b85b2d159f5b023ec19d6950fa33fa35ee33fcfd66862acafc37095dbb9e2b54fa139392460632a0f86a53f31fcf88787d605958f2cd974859c0b127fbcf9099fc04f7afa2c4c1b585d003fb90e21a53a3ca02894732ad858d7dec90be4c52e5d91ed597981ebb
#TRUST-RSA-SHA256 27f216fa453b1ed39f6273486d724f547d616e35fcb4e6d706d7df2dbbffe2a528a84aea287c7c5d95afdff9aeae94ba2caae5a7b9a6331f8ee93ca9d9073baaebf604574df41f81583fd6ab0bd0e58ada2e8868821f8748770269e3bb2177f962497a091a9273767b5e67913d3c9758fbfcb431ea09117e1972f684a66228666432d808d89a398ff8395ef3da05057e8f9ce319e3677e858e407c690896645489bf501f97b299513b3a5b5505e1fde2f8a7c5e795d958389fddeef47727aa78f02d6c83e8da2046c7d7e7236ff03e4f129c6d2118a941adf87f12730ce77d6060d420308cc2e21dbf152b0832821c8e13ce888e2ee19dcd2d8f09a08ebe19a341eed9c50ad440a97a9dbb3acb0766be12f9d1695cbc6ba0a8d13354d351811119c9a46670b20205006c7f91dacf753d8ec6d11c7dbe8ae20d802d71a4a76058ebfa0b21a554c7bb3d21d1f6ead4810b32d08a642ae7cf365fec7c1dcb1be902125077cdd3767a6e20cf79ec6789c25f7c77b8a5b7bcba5b83d1c02c65f60a7fa0badc9770dc4256ebc64e49a7451e9a35bb562876dad6d05b7b4208927b3385202e06187e37a05a1c40c66f9173f5d369b909d2fe340c8f0310aa414429f9d337dc5dd207e5696dc54b178d09b50a10ec53f8ea705db1a5e2648535cf98c3f1ee56eb31f7f2245dc9336b94f7d88dc98046c3da3fdd6abfc68d8e6e15c0562e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64700);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2012-3213",
    "CVE-2012-3342",
    "CVE-2013-0351",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0429",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0438",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0450",
    "CVE-2013-1473",
    "CVE-2013-1475",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1480",
    "CVE-2013-1481",
    "CVE-2013-1486",
    "CVE-2013-1487",
    "CVE-2013-1488"
  );
  script_bugtraq_id(
    57686,
    57687,
    57689,
    57691,
    57692,
    57694,
    57696,
    57699,
    57700,
    57702,
    57703,
    57708,
    57709,
    57710,
    57711,
    57712,
    57713,
    57714,
    57715,
    57716,
    57717,
    57718,
    57719,
    57720,
    57724,
    57727,
    57728,
    57729,
    57730,
    57731,
    58029,
    58031
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-19-1");

  script_name(english:"Mac OS X : Java for OS X 2013-001");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-001 update, which updates the Java
version to 1.6.0_41.  It is, therefore, affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5666");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525745/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2013-001 update, which includes version
14.6.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.[78]([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8");

cmd = 'ls /System/Library/Java';
results = exec_cmd(cmd:cmd);
if (isnull(results)) exit(1, "Unable to determine if the Java runtime is installed.");

if ('JavaVirtualMachines' >!< results) audit(AUDIT_NOT_INST, "Java for OS X");


plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "14.6.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
