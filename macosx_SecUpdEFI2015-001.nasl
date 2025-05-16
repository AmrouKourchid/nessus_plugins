#TRUSTED 58b0c858cf200d9d07165ef8a573a8ccd96579900f1d3826dc970ada40401d5efe1133d707526f5860ef2bb75d164975212561dbb66a36bb94262152f42cd31698582d0bf693db198ba97d8677995151859e5be8c584f27f7ca6cdf9374e02a81f9a0b06f371ab061e6f47fe29221d4b5ac6a3b5e0c595939c3f0f549301b9f096b49bfd1778ccb116a4c41177a9ebc1d596cf580113d110ccdaf667cac4a453f18a4664a55613006e95c34f999fc35e34c7055b41eafb245d33d60ad8c48793340f14e7bd9a95bf73a4baa1f45673aae9fba921427acbe80176a79a3d21b976a7836f0419f63ebfe3e6dfd3056c0e83e5c4d312e93a3ea96f842dad8b0c0bca1ec337ad1a976dd272aef2e16c0f46f61ba828c4dfc6382e74403afb3f93fcd672ef625584992dac7761b91ff42034e374f23e71cdb93b48abbbe4ec220b57c076e53690b95fc54656780b514f4ec3453ffc629afd25cace38ad4b92befe7caf845725cc5b78fd6e92f244f7e6a6ece500bcfe1d367c7658ba69a120e719363ebb2205348a85a6e3d66da44655a1a5a0ce84de69875f4fbc2bcf532017f5decb3033c40bffe4a60487aa92e1019cb0c2b278f22005f93e9294b2eefb87b4a70d284fcf98db1cb865cf7c3d941ae36546dc51a33e6e3844dad50116b224469f40c96c9f6f338371a35d5f345f7e75beaaf1c2fdf9dbf8548ae29653aef30e9f6a
#TRUST-RSA-SHA256 a3f1a2819b05d650418778403a8d1acb8d00f02f51beaa6ca010a800541aae86a8c3a004e7cd41b5d1ae780929c098037d31f55f3248a1a1eeb83f1328486436e7f978d8bfad2201566ce79bd87bc87ced0c8450787fd3b29f790b84572ed5fe37324e2f0643b51f1e9d4c3b7b3772147099b61bc8bd62dc87d8a0c00c49e8e2acfd32319a02c8cde8980a56fc0469111bdf03ad5a6cb52b99c40c630c46ef87948acf52ea61a8aa23f163bceb8cca985e553a0974cf4c1895bd721ac2f7c45675fac55e21b3a6b85d9cf8c31a73104b8e26994a7e8b895ca5be31f8537668bfb56d0a647732bad7034182744232a5096c79ce972818af532f93e0fbb5027e5931f478e1315d6892e4571907cd3d5a8b881f2f704dd82cbd36fc9bb2e05bcc1d2ad9847b124226b0db60e78535ef12e811e18a9ec8617c1ad9680ae219e481f8f0f31026b62b12b4189e4c01dbeaf618f03ff05d62e1b16cf9a35ced784397e77e93955c77a975d67f4f4c6b57342bfaeb3ba0638c4afbd7ad0fc925f3cd3bed9f9191a29889f46c8b039b7864a10377349fa83812c48a01ace2555d2435024be5d4b3a99be3871b46b7026c205416604714332c08c50e60720eaa012667998eb0acf9227934459ad9a3d4b032a50ee3f950294db77531fc458c47e02c8f4c0ff9c102033b70d371080a64220746b7d7097ff8f37814db3e51ba19a34a41cae0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84565);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-3692", "CVE-2015-3693");
  script_bugtraq_id(74971);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-06-30-3");

  script_name(english:"Mac OS X Multiple EFI Vulnerabilities (EFI Security Update 2015-001)");
  script_summary(english:"Checks the EFI version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running EFI firmware that is affected by
multiple vulnerabilities :

  - An insufficient locking issue exists, when resuming from
    sleep states, which allows a local attacker to write to
    the EFI flash memory by using an crafted application
    with root privileges. (CVE-2015-3692)

  - A flaw exists due to lax restrictions on memory refresh
    rates, which allows a specially crafted process to
    corrupt the memory of some DDR3 SDRAM devices by
    inducing bit flips in page table entries (PTEs), also
    known as a 'row-hammer attack'. An attacker can exploit
    this to gain elevated privileges by manipulating the
    PTEs. (CVE-2015-3693)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204934");
  script_set_attribute(attribute:"solution", value:
"Install Mac EFI Security Update 2015-001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3693");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

efi_fixes = make_nested_array(
   "Mac-942459F5819B171B",
    make_array(
      "efi-version", "MBP81.88Z.0047.B2A.1506082203"
    ),
    "Mac-FC02E91DDD3FA6A4",
    make_array(
      "efi-version", "IM131.88Z.010A.B08.1506081728"
    ),
    "Mac-42FD25EABCABB274",
    make_array(
      "efi-version", "IM151.88Z.0207.B03.1506050728"
    ),
    "Mac-3CBD00234E554E41",
    make_array(
      "efi-version", "MBP112.88Z.0138.B15.1506050548"
    ),
    "Mac-8ED6AF5B48C039E1",
    make_array(
      "efi-version", "MM51.88Z.0077.B12.1506081728"
    ),
    "Mac-35C1E88140C3E6CF",
    make_array(
      "efi-version", "MBA61.88Z.0099.B19.1506050547",
      "minimum-smc-version", "2.12f135"
    ),
    "Mac-81E3E92DD6088272",
    make_array(
      "efi-version", "IM144.88Z.0179.B10.1506050729"
    ),
    "Mac-35C5E08120C7EEAF",
    make_array(
      "efi-version", "MM71.88Z.0220.B03.1506051117"
    ),
    "Mac-94245BF5819B151B",
    make_array(
      "efi-version", "MBP81.88Z.0047.B2A.1506082203"
    ),
    "Mac-4BC72D62AD45599E",
    make_array(
      "efi-version", "MM51.88Z.0077.B12.1506081728"
    ),
    "Mac-2E6FAB96566FE58C",
    make_array(
      "efi-version", "MBA51.88Z.00EF.B03.1506081623"
    ),
    "Mac-7BA5B2794B2CDB12",
    make_array(
      "efi-version", "MM51.88Z.0077.B12.1506081728"
    ),
    "Mac-031AEE4D24BFF0B1",
    make_array(
      "efi-version", "MM61.88Z.0106.B08.1506081405"
    ),
    "Mac-7DF2A3B5E5D671ED",
    make_array(
      "efi-version", "IM131.88Z.010A.B08.1506081728"
    ),
    "Mac-00BE6ED71E35EB86",
    make_array(
      "efi-version", "IM131.88Z.010A.B08.1506081728"
    ),
    "Mac-942B59F58194171B",
    make_array(
      "efi-version", "IM121.88Z.0047.B21.1506101610"
    ),
    "Mac-742912EFDBEE19B3",
    make_array(
      "efi-version", "MBA41.88Z.0077.B12.1506081728"
    ),
    "Mac-189A3D4F975D5FFC",
    make_array(
      "efi-version", "MBP111.88Z.0138.B15.1506050728"
    ),
    "Mac-937CB26E2E02BB01",
    make_array(
      "efi-version", "MBA71.88Z.0166.B06.1506051511"
    ),
    "Mac-4B7AC7E43945597E",
    make_array(
      "efi-version", "MBP91.88Z.00D3.B0B.1506081214"
    ),
    "Mac-E43C1C25D4880AD6",
    make_array(
      "efi-version", "MBP121.88Z.0167.B07.1506051617"
    ),
    "Mac-7DF21CB3ED6977E5",
    make_array(
      "efi-version", "MBA61.88Z.0099.B19.1506050547",
      "minimum-smc-version", "2.13f7"
    ),
    "Mac-C3EC7CD22292981F",
    make_array(
      "efi-version", "MBP101.88Z.00EE.B09.1506081405"
    ),
    "Mac-942B5BF58194151B",
    make_array(
      "efi-version", "IM121.88Z.0047.B21.1506101610"
    ),
    "Mac-06F11F11946D27C5",
    make_array(
      "efi-version", "MBP114.88Z.0172.B04.1506051511"
    ),
    "Mac-9F18E312C5C2BF0B",
    make_array(
      "efi-version", "MBA71.88Z.0166.B06.1506051511"
    ),
    "Mac-94245B3640C91C81",
    make_array(
      "efi-version", "MBP81.88Z.0047.B2A.1506082203"
    ),
    "Mac-6F01561E16C75D06",
    make_array(
      "efi-version", "MBP91.88Z.00D3.B0B.1506081214"
    ),
    "Mac-94245A3940C91C80",
    make_array(
      "efi-version", "MBP81.88Z.0047.B2A.1506082203"
    ),
    "Mac-BE0E8AC46FE800CC",
    make_array(
      "efi-version", "MB81.88Z.0164.B06.1506051617"
    ),
    "Mac-27ADBB7B4CEE8E61",
    make_array(
      "efi-version", "IM142.88Z.0118.B11.1506050547"
    ),
    "Mac-06F11FD93F0323C5",
    make_array(
      "efi-version", "MBP114.88Z.0172.B04.1506051511"
    ),
    "Mac-031B6874CF7F642A",
    make_array(
      "efi-version", "IM141.88Z.0118.B11.1506050727"
    ),
    "Mac-F60DEB81FF30ACF6",
    make_array(
      "efi-version", "MP61.88Z.0116.B15.1506050548"
    ),
    "Mac-77EB7D7DAF985301",
    make_array(
      "efi-version", "IM143.88Z.0118.B11.1506050727"
    ),
    "Mac-FA842E06C61E91C5",
    make_array(
      "efi-version", "IM151.88Z.0207.B03.1506050728"
    ),
    "Mac-F65AE981FFA204ED",
    make_array(
      "efi-version", "MM61.88Z.0106.B08.1506081405"
    ),
    "Mac-C08A6BB70A942AC2",
    make_array(
      "efi-version", "MBA41.88Z.0077.B12.1506081728"
    ),
    "Mac-66F35F19FE2A0D05",
    make_array(
      "efi-version", "MBA51.88Z.00EF.B03.1506081623"
    ),
    "Mac-2BD1B31983FE1663",
    make_array(
      "efi-version", "MBP112.88Z.0138.B15.1506050548"
    ),
    "Mac-AFD8A9D944EA4843",
    make_array(
      "efi-version", "MBP102.88Z.0106.B08.1506081215"
    )
);

# Modeled after check actual patch performs
# if the SMC gets "borked" it reports as "0.000"
# output:
#      -2 if there's an error
#      -1 if actual < intended
#      0 if actual == intended
#      1 if actual > intended
function compareTwoSMCVersions(actual, intended)
{
  local_var pat, item_actual, item_intended,
            actualMajorVersion, actualMinorVersion,
            actualBuildType, actualBuildNumber,
            intendedMajorVersion, intendedMinorVersion,
            intendedBuildType, intendedBuildNumber;

  # borked version checks
  if(actual == "0.000" && intended == "0.000") return 0;
  if(actual == "0.000" && intended != "0.000") return -1;
  if(actual != "0.000" && intended == "0.000") return 1;

  pat = "^(\d+)\.(\d+)([a-f]{1})(\d+)$";
  item_actual = eregmatch(pattern: pat, string: actual);
  item_intended = eregmatch(pattern: pat, string: intended);

  if(isnull(item_actual) || isnull(item_intended)) return -2;

  actualMajorVersion = int(item_actual[1]);
  actualMinorVersion = int(item_actual[2]);
  actualBuildType = item_actual[3];
  actualBuildNumber = int(item_actual[4]);

  intendedMajorVersion = int(item_intended[1]);
  intendedMinorVersion = int(item_intended[2]);
  intendedBuildType = item_intended[3];
  intendedBuildNumber = int(item_intended[4]);

  if(actualMajorVersion != intendedMajorVersion) return -2;
  if(actualMinorVersion != intendedMinorVersion) return -2;

  if(actualBuildType !~ "^[abf]$" || intendedBuildType !~ "^[abf]$")
    return -2;

  if(actualBuildType < intendedBuildType) return -1;
  if(actualBuildType > intendedBuildType) return 1;

  if(actualBuildNumber < intendedBuildNumber) return -1;
  if(actualBuildNumber > intendedBuildNumber) return 1;

  return 0;
}

# Modeled after check patch performs
# output:
#      -2 if there's an error
#      -1 if actual < intended
#      0 if actual == intended
#      1 if actual > intended
function compareTwoEFIVersions(actual, intended)
{
  local_var actual_array, intended_array,
            actual_minor_version, intended_minor_version,
            actual_major_version, intended_major_version;

  actual_array = split(actual, sep:'.', keep:FALSE);
  intended_array = split(intended, sep:'.', keep:FALSE);

  if(max_index(actual_array) != 5 || max_index(intended_array) != 5)
    return -2;

  if(actual_array[0] != intended_array[0]) return -2;
  if(actual_array[1] != "88Z" || intended_array[1] != "88Z") return -2;

  if(actual_array[2] !~ "^[\da-fA-F]{4}$" ||
     intended_array[2] !~ "^[\da-fA-F]{4}$") return -2;

  # don't know why, but this check is in the patch
  if(actual_array[3][0] =~ "[dD]" || intended_array[3][0] =~ "[dD]")
    return -2;

  actual_minor_version = substr(actual_array[3], 1);
  intended_minor_version = substr(intended_array[3], 1);

  if(actual_minor_version !~ "^[\da-fA-F]{2}$" ||
     intended_minor_version !~ "^[\da-fA-F]{2}$") return -2;

  actual_minor_version = ord(hex2raw(s:actual_minor_version));
  intended_minor_version = ord(hex2raw(s:intended_minor_version));

  actual_major_version = getword(blob:hex2raw(s:actual_array[2]),
                                 pos:0, order:BYTE_ORDER_BIG_ENDIAN);
  intended_major_version = getword(blob:hex2raw(s:intended_array[2]),
                                   pos:0, order:BYTE_ORDER_BIG_ENDIAN);
  
  if(actual_major_version > intended_major_version) return 1;
  if(actual_major_version < intended_major_version) return -1;
  if(actual_minor_version > intended_minor_version) return 1;
  if(actual_minor_version < intended_minor_version) return -1;

  return 0;
}

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Available for: OS X Mountain Lion v10.8.5, OS X Mavericks v10.9.5
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.[89]\.5([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8.5 or Mac OS X 10.9.5");

board_id_cmd = 'ioreg -l | awk -F \\" \'/board-id/ { print $4 }\'';
efi_version_cmd = 'ioreg -p IODeviceTree -n rom@0 | awk -F \\" \'/version/ { print $4 }\'';
smc_version_cmd = 'ioreg -l | awk -F \\" \'/smc-version/ { print $4 }\'';

results = exec_cmds(cmds:make_list(board_id_cmd, efi_version_cmd, smc_version_cmd));

# these may not be considered an 'error' if host is a VM running on non Apple hardware
if(isnull(results)) exit(0, "Unable to obtain hardware information on remote host.");

if(isnull(results[board_id_cmd]) || results[board_id_cmd] !~ "^Mac-[a-fA-F\d]+$")
  exit(0, 'No valid Mac board ID found.');

if(isnull(results[efi_version_cmd]) || ".88Z." >!< results[efi_version_cmd])
  exit(0, 'No valid Mac EFI version found.');

if(isnull(results[smc_version_cmd]) || results[smc_version_cmd] !~ "^(\d+)\.([\da-f]+)$")
  exit(0, 'No valid Mac SMC version found.');

board_id = results[board_id_cmd];
efi_version = results[efi_version_cmd];
smc_version = results[smc_version_cmd];

if(isnull(efi_fixes[board_id])) exit(0, "The remote host does not have an affected board ID (" + board_id + ").");

efi_fix = efi_fixes[board_id]["efi-version"];
min_smc_ver = efi_fixes[board_id]["minimum-smc-version"];

if(!isnull(min_smc_ver))
{
  if(compareTwoSMCVersions(actual:smc_version, intended:min_smc_ver) < 0)
    exit(0, "SMC version " + smc_version + " is too old to allow update.");
}

res = compareTwoEFIVersions(actual:efi_version, intended:efi_fix);
if(res == -2)
  exit(1, "Error comparing EFI version (" + efi_version + ") to fixed version (" + efi_fix + ").");

if(res >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, "Apple EFI", efi_version);

port = 0;

if(report_verbosity > 0)
{
  report = '\n  Board ID              : ' + board_id +
           '\n  Installed EFI version : ' + efi_version +
           '\n  Fixed EFI version     : ' + efi_fix + '\n';
  security_hole(port:port, extra:report); 
}
else security_hole(port);
