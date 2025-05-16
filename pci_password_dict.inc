#TRUSTED 8de1c48ab9a59dcc50daded873469fa547a3387c6db2fe762227096d085a290df76433a17e086626591d26e4aed7cc07c4fc10dbd46429e867e68e2df17ea78a89313f5ea353e77c27fd8775f8103059ec5a2c9df4a94ae9c4ecf39a2b5d206466b57a3ec2710e742c3f3a1d37b3cf7166baf6786b7d0e8bf22d29aca8a9883fbe97922a9ddb1fb0bf753a3487839390a3ce890f592a3e3267da12c0d0a700331cb3c6198800399a459018bb64eb8b176bbadd585b2ec1fd5bb53406540521fea4b6b96cb87411ed42d5b0a96d7a3196cf2eea77ff3c5214bab3547d7845284d5d21678463a8752d469c6100668bab96f5f1943bdfd58522e251cfacccbb253c89471fd86db287ac715b8b94dc1bd6933c7e11eb4ac0940dc320ecf50d7f51bb2393d39fedb00d9d9ccd307b4d594c2ee3cc9686e117de2c4a85f39824f0052ca6c8a7685da617e0fe637bc92e73b1238388ebe9a5db051f68b8ec7e7fad7f8a3ccc324a250e4df589120b28705680f196efcd19577009965c56472087d101705bbc8ed291ece664e1603e1b06389a1df36bac67885c7ce7d3d04ef24c4d50d811cb7e7223438999c6d144c13855ad0625bc93f16396a25f1574800f15e21155a9932246a30b0b798a2d9bbac76dff9ccc80ffa6e459b788fc950d091255e4d06b8589a8a9d4812b5a2bbe9e96d779548cb9757e2a0a6b95398bbac7ffcc52f8
#TRUST-RSA-SHA256 9342ee2a810626c8872f202a0d08d4c8f9ef48746913cf0d737aaca79e9662ae34ed43c1e3b21bb5953ca2353b6ee6b00579d8e37a04f3bba2e8f57f144d702078ac5e73af5ef374589c773d07022189ada9c0b3e2ea317fd702624a885088869f1110e51f568a4e81d5d94fb9f73068e7c11771e780c26a6c67f9da987817d61ee9ae1c012f5e57565f992ee57424131d6d0463e1cba17b7ef86a779a73f7ea090042bc16dddb8fdbe8e501e429549f1d88b30402a0a082174977657f6fb634ba32482a388dbc8dd5189788c6954c2e29154e5bdf8e011a25c632b3e687be60f2deae99d53851df9587af636aa96e4d11d1b8c529137ce4e76cef14253ab4ca38f0367ae59994fb26a09ec0dcd8d8e9acb9359b0b3c6d26f7c4f879e614fb82c53e32f38daa1b497feda24e3fa4adefb10f81328dedbaf9d1db8d1cf2fbad1700d650b9942bdf692348ddde81c04d77df0613a02f0473b75153f85b9556efa5e01bcddfc537b60ca84c13a7034010941d771bededce68a31bc0f06f2a6ff2455b1f6a1345111106707dc05c1607ab1f97a9428b09503d1130327710a1dc7ad2a8b939730237cd50093274f368a1a31dfe8aa3aea25bba9da3c27ac1149e1e1ed89c2731735acb533acc780a63432045b3d4f5e10d26557979466d61fb1b7f222c490df7c3532747856bdcdafb83e34e3558b8948f42fd5928fed4e2d492aabe
##
# NOTE: os_fingerprint.nasl is expected to have run
# prior to calling get_pci_password_list() for the
# first time. 
##

include('lists.inc');
include('sets.inc');

global_var global_pci_login_list_init, global_pci_login_list;
global_pci_login_list = [];
global_pci_login_list_init = FALSE;


function cartesian_product_logins(usernames, passwords, username_as_password) 
{
  var logins = [];
  var user, pass;
  foreach (user in usernames)
  {
    if (username_as_password)
      collib::push({'username':user, 'password':user}, list:logins);
    foreach (pass in passwords)
    {
      collib::push({'username':user, 'password':pass}, list:logins);
    }
  }
  return logins;
}

function get_pci_login_list(default_username, platform)
{
  # we'll use a case/switch construction here, instead
  # of an array, so that we don't bother storing unneeded
  # passwords in memory. 
  var logins, base_list, tmp, max_logins;

  if (isnull(default_username))
    default_username = 'admin'; # by far the most common

  max_logins = 6;

  if (isnull(platform)) platform = get_kb_item("Host/OS");
  if (isnull(platform))
  {
    if (get_kb_item("Host/OS/Fingerprint/Fail")) 
      platform = 'UNKNOWN';
    else
      exit(1, "Cannot initialize the PCI brute force password list "+
              "without knowing the operating system. Please ensure "+
              "that os_fingerprint.nasl is executed first.");
  }

  # to simplify things a little, we'll just take the first
  # word in the OS name, normalized to uppercase.
  tmp = split(platform, sep:' ', keep:FALSE);
  if (isnull(tmp)) tmp = platform;
  else tmp = tmp[0];
  platform = toupper(tmp);

  # https://en.wikipedia.org/wiki/List_of_the_most_common_passwords
  var base_password_list = [
    'admin',
    '123456',
    'password',
    '123456789',
    '12345678',
    '12345',
    'P@ssw0rd'
  ];

  base_list = cartesian_product_logins(
      usernames:[default_username],
      passwords:base_password_list, 
      username_as_password:TRUE);

  ## check use supplied passwords only!
  ## if that box isn't checked, and if it's not a pci scan, then 
  ## go ahead and use this

  ##
  # most of these default (or very common) passwords are taken from
  # https://www.router-reset.com/default-password-ip-list/  and
  # https://cleancss.com/router-default/
  # 
  # The list is manipulated in such a way as to allow entries of one of
  # two types: either a complete login array, consisting of a 'username'
  # keyed value and a 'password' keyed value, or a bare string (pure or
  # impure), which will be interpreted as the password field, and coupled
  # with the value of the default_password parameter to form a full login
  # record. 
  # 
  # It is always better to provide a complete login array, when the infor-
  # mation is available. 
  ##
  switch (platform)
  {
    case '3COM':
      # https://www.router-reset.com/default-password-ip-list/3Com
      logins = [
        { 'username': '', 'password': 'admin' },
        { 'username': '', 'password': 'comcomcom' }
      ];
      break;
    case 'A10':
      logins = [
         { 'username': 'admin', 'password': 'a10' },
         { 'username': 'admin', 'password': 'newpassword' },
      ];
      break;
    case 'ADTRAN':
      # https://www.router-reset.com/default-password-ip-list/Adtran
      logins = [
        { 'username': 'admin', 'password': 'password' },
        { 'username': 'admin', 'password': 'admin' }
      ];
      break;
    case 'AEROHIVE':
      # https://www.router-reset.com/default-password-ip-list/Aerohive
      logins = [
        { 'username': 'admin', 'password': 'aerohive' },
        { 'username': 'root', 'password': 'aerohive' }
      ];
      break;
    case 'AIX':
      logins = [
      ];
      break;
    case 'ALVARION':
      # https://www.cleancss.com/router-default/Alvarion/Networking_Gateway
      logins = [
        'private',
        'wimax',
        'admin',
        'public',
        'installer'
      ];
      break;
    case 'AMAZON':
      logins = [
      ];
      break;
    case 'APC':
      logins = [
        { 'username': 'admin', 'password': 'apc' },
        { 'username': 'admin', 'password': 'backdoor' },
        { 'username': 'admin', 'password': 'TENmanUFactOryPower' },
        { 'username': 'admin', 'password': 'MGEUPS' },
        { 'username': 'admin', 'password': 'Ura' },
        { 'username': 'admin', 'password': 'APC' }
      ];
      break;
    case 'APPLE':
      logins = [
      ];
      break;
    case 'ARISTA':
      logins = [
        '' 
      ];
      break;
    case 'ASCEND':
      logins = [
        'ascend',
        'lucenttech2',
        { 'username': 'Administrator', 'password': 'admin' }
      ];
      break;
    case 'ASYNCOS':
      logins = [
      ];
      break;
    case 'AVOCENT':
      logins = [
        { 'username': 'admin', 'password': '' },
        { 'username': 'root', 'password': 'tslinux' },
        { 'username': 'admin', 'password': 'avocent' },
        { 'username': 'admin', 'password': 'cyclades' },
        { 'username': 'root', 'password': 'linux' },
        { 'username': 'admin', 'password': 'pm8' },
        { 'username': 'root', 'password': 'Sydney' },
      ];
      break;
    case 'AXIS':
      logins = [
        'pass',
      ];
      break;
    case 'BROCADE':
      logins = [
        'password'
      ];
      break;
    case 'CHECK':
      logins = [
        'admin'
      ];
      break;
    case 'CISCO':
      logins = [
        'admin',    # admin
        'PASSW0RD'  # USERID
      ];
      break;
    case 'CITRIX':
      logins = [
        'nsroot'
      ];
      break;
    case 'COMPAQ':
      logins = [
        '' # username: admin
      ];
      break;
    case 'CONNECTUPS':
      logins = [
        'admin' # username: admin
      ];
      break;
    case 'CONTAINER':
      logins = [
      ];
      break;
    case 'CORERO':
      logins = [
      ];
      break;
    case 'DEBIAN':
      logins = [
      ];
      break;
    case 'DELL':
      logins = [
      ];
      break;
    case 'DIGITAL':
      logins = [
      ];
      break;
    case 'D-LINK':
      logins = [
        '',
        'password',
        'admin',
        'unknown',
        'user'
      ];
      break;
    case 'DSR2035':
      logins = [
        { 'username': 'root', 'password': 'tslinux' },
        { 'username': 'root', 'password': 'linux' },
        { 'username': 'admin', 'password': 'avocent' },
        { 'username': 'admin', 'password': 'password' },
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'admin', 'password': '1234' },
        { 'username': 'snmp', 'password': '1234' },
        { 'username': 'admin', 'password': 'Admin1' },
        { 'username': 'admin', 'password': 'cyclades' },
      ];
      break;
    case 'EMC':
      # source: vstrong.info/default-logins/
      logins = [
        { 'username': 'admin', 'password': 'EMCPMAdm7n' },
        { 'username': 'admin', 'password': 'Password123#' },
        { 'username': 'admin', 'password': 'password' },
        { 'username': 'localadmin', 'password': 'password' },
        { 'username': 'sysadmin', 'password': 'sysadmin' },
        { 'username': 'admin', 'password': 'changeme' },
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'boxmgmt', 'password': 'boxmgmt' },
        { 'username': 'security-admin', 'password': 'security-admin' },
        { 'username': 'xmsadmin', 'password': '123456' },
        { 'username': 'tech', 'password': '123456' },
        { 'username': 'xmsadmin', 'password': 'Xtrem10' },
        { 'username': 'xmsupload', 'password': 'xmsupload' },
        { 'username': 'tech', 'password': 'X10Tech!' },
        { 'username': 'xinstall', 'password': 'xiofast1' },
        { 'username': 'root', 'password': 'ChangeMe' },
        { 'username': 'root', 'password': 'emc' }
        # emcbios for bios access, but that's probably irrelevant here
      ];
      break;
    case 'ENTERASYS':
      logins = [
        'public'
      ];
      break;
    case 'EQUINOX':
      logins = [
      ];
      break;
    case 'EULEROS':
      logins = [
      ];
      break;
    case 'EXTREMEXOS':
      logins = [
        '',
        'abc123'
      ];
      break;
    case 'FBLOS':
      logins = [
        'admin'
      ];
      break;
    case 'FORTINET':
      logins = [
        { 'username': 'admin', 'password': '' },
        { 'username': 'maintainer', 'password': 'admin' }
          # or bcbp + the serial number
      ];
      break;
    case 'FOUNDRY':
      logins = [
        '-'
      ];
      break;
    case 'FREEBSD':
      # PF Sense may fall under this as well
      logins = [
      ];
    case 'GENTOO':
      logins = [
      ];
      break;
    case 'GUARDIANOS':
      # https://support.overlandstorage.com/jive/servlet/KbServlet/download/7933-102-2701/AdminGuide_52056.pdf
      logins = [
        { 'username': 'admin', 'password': 'admin' }
      ];
      break;
    case 'HAIKU':
      logins = [
      ];
      break;
    case 'HIKVISION':
      logins = [
        '12345' # admin
      ];
      break;
    case 'HONEYWELL':
      logins = [
        { 'username': 'administrator', 'password': '1234' },
        { 'username': 'SysAdmin', 'password': 'honey' },
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'Guest', 'password': 'guest' }
      ];
      break;
    case 'HP':
      logins = [
      ];
      break;
    case 'HP-UX':
      logins = [
      ];
      break;
    case 'HUAWEI':
      # https://portforward.com/router-password/huawei.htm
      logins = [
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'admin', 'password': '' },
        { 'username': 'user', 'password': 'user' },
        { 'username': 'vodafone', 'password': 'vodafone' },
        { 'username': 'admin', 'password': 'superonline' },
        { 'username': 'admin', 'password': '3bb' },
        { 'username': 'user', 'password': 'HuaweiUser' },
        { 'username': 'telecomadmin', 'password': 'admintelecom' },
        { 'username': 'digicel', 'password': 'digicel' }
      ];
      break;
    case 'IBM':
      logins = [
        { 'username': 'gaiandb', 'password': 'gIan08pW0rd' },
        { 'username': 'apmadmin', 'password': 'apmpass' },
        { 'username': 'smadmin', 'password': 'apmpass' },
        { 'username': 'itmuser', 'password': 'db2Usrpasswd@08' },
        { 'username': 'db2apm', 'password': 'db2Usrpasswd@08' },
        { 'username': 'db2fenc1', 'password': 'db2Usrpasswd@08' },
        { 'username': 'dasusr1', 'password': 'db2Usrpasswd@08' },
        { 'username': 'admin', 'password': 'mongoUsrpasswd@08' },
        { 'username': 'user', 'password': 'mongoUsrpasswd@08' }
      ];
      break;
    case 'INTERMEC':
      logins = [
        { 'username': 'admin', 'password': 'pass' },
        { 'username': 'itadmin', 'password': 'pass' }
      ];
      break;
    case 'IRIX':
      logins = [
        { 'username': 'EZsetup', 'password': '' }
      ];
      break;
    case 'ISILON':
      logins = [
      ];
      break;
    case 'JANITZA':
      logins = [
        { 'username': 'admin', 'password': 'Janitza' },
        { 'username': 'admin', 'password': '0th' }
      ];
      break;
    case 'JUNIPER':
      logins = [
        { 'username': 'admin', 'password': 'abc123' },      # admin
        { 'username': 'super', 'password': 'juniper123' }   # super
      ];
      break;
    case 'JUNOS':
      logins = [
        { 'username': 'admin', 'password': 'abc123' },      # admin
        { 'username': 'super', 'password': 'juniper123' }   # super
      ];
      break;
    case 'KONICA':
    case 'MINOLTA':
      # https://www.clnet-solution.my/knowledgebase/konica-minolta-default-password/
      logins = [
        { 'username': 'admin', 'password': 'sysAdmin' },
        { 'username': 'sysadm', 'password': 'administrator' },
        { 'username': 'admin', 'password': '1234567812345678' },
        { 'username': '', 'password': '0' },
        { 'username': '', 'password': 'sysadm' },
        { 'username': '', 'password': '12345678' },
        { 'username': '', 'password': 'MagiMFP' },
        { 'username': '', 'password': '' },
        { 'username': '', 'password': '0000' },
        { 'username': '', 'password': 'KMBC30P' },
        { 'username': '', 'password': '1057' },
        { 'username': 'administrator', 'password': 'Administrator' },
        { 'username': 'Administrator', 'password': 'Administrator' },
        { 'username': '', 'password': 'KM2450' },
        { 'username': '', 'password': 'KMM5550' },
        { 'username': '', 'password': 'KMM7450' }
      ];
      break;
    case 'LEXMARK':
      logins = [
        { 'username': '', 'password': '' }
      ];
      break;
    case 'LINKSYS':
      logins = [
        { 'username': 'admin', 'password': 'admin' }
      ];
      break;
    case 'LINUX':
      logins = [
      ];
      break;
    case 'MAC':
      logins = [
      ];
      break;
    case 'MARCONI':
      # https://portforward.com/router-password/marconi.htm
      logins = [
        { 'username': 'admin', 'password': 'epicrouter' },
        { 'username': 'admin', 'password': 'password' },
        { 'username': 'admin', 'password': 'administrator' }
      ];
      break;
    case 'MCAFEE':
      logins = [
      ];
      break;
    case 'MEDIANT':
      # https://www.audiocodes.com/media/8029/ltrt-39103-mediant-1000b-sba-quick-guide.pdf
      logins = [
        { 'username': 'Administrator', 'password': 'Pass123' }
      ];
      break;
    case 'MEDIATRIX':
      logins = [
        { 'username': 'admin', 'password': 'administrator' },
        { 'username': 'root', 'password': '5678' }
      ];
      break;
    case 'MICROSOFT':
      logins = [
      ];
      break;
    case 'MIKROTIK':
      # https://www.init7.net/en/support/faq/Passwort-MikroTik-Router/
      logins = [
        { 'username': 'admin', 'password': 'asdf4ever' }
      ];
      break;
    case 'MITEL':
      # http://open-sez.me/passwd-mitel.htm
      logins = [
        { 'username': 'system', 'password': 'password' },
        { 'username': 'admin', 'password': 'itpassw' },
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'system', 'password': 'mnet' },
        { 'username': 'installer', 'password': '0000' },
        { 'username': 'system', 'password': 'sx2000' }
      ];
      break;
    case 'MSSQL':
      # https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt
      logins = cartesian_product_logins(
        usernames:[
          'sa',
          'cic',
          'root',
          'admin',
          'administrator',
          'webadmin',
          'sysadmin',
          'netadmin',
          'guest',
          'user',
          'web',
          'secure',
          'test',
          'jirauser'
        ],
        passwords:[ 
          'password',
          'default',
          'sqlserver',
          'jirauser',
          ''
        ],
        username_as_password:TRUE
      );
      break;
    case 'NET': # Net Optics
      #  Cf. account_admin_netoptics.nasl
      logins = [
        { 'username': 'admin', 'password': 'netoptics' }
      ];
      break;
    case 'NETAPP':
      # https://library.netapp.com/ecmdocs/ECMLP2427456/html/GUID-E3EAE561-94E0-48D5-B5F2-0AB75E12CC50.html
      logins = [
        { 'username': 'admin', 'password': 'netapp!123' },
        { 'username': 'Admin', 'password': 'password' }
      ];
      break;
    case 'NETBSD':
      logins = [
      ];
      break;
    case 'NETGEAR':
      # https://community.netgear.com/t5/General-WiFi-Routers-Non/Netgear-Default-Password-list/m-p/1652055
      logins = [
        { 'username': 'admin', 'password': 'password' },
        { 'username': 'superuser', 'password': 'password' }
      ];
      break;
    case 'NISUTA':
      # https://www.manualslib.com/manual/1118437/Nisuta-Ns-Wir150n.html?page=199
      logins = [
        { 'username': 'admin', 'password': 'admin' }
      ];
      break;
    case 'NOKIA':
      # https://www.nisuta.com/pdf/NSWMR54M.pdf
      logins = [
        { 'username': 'admin', 'password': 'admin' }
      ];
      break;
    case 'NORTEL':
      # https://www.cleancss.com/router-default/NORTEL
      logins = [
        { 'username': '0', 'password': '0' },
        { 'username': '**23646', 'password': '23646' },
        { 'username': '266344', 'password': '266344' },
        { 'username': '**ADMIN (**23646)', 'password': 'ADMIN (23646)' },
        { 'username': 'administrator', 'password': 'PlsChgMe!' },
        { 'username': 'admin', 'password': '000000' },
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'admin', 'password': 'admin000' },
        { 'username': 'admin', 'password': 'root' },
        { 'username': 'admin', 'password': 'setup' },
        { 'username': 'ccrusr', 'password': 'ccrusr' },
        { 'username': 'distrib', 'password': 'distrib0' },
        { 'username': 'l2', 'password': 'l2' },
        { 'username': 'login', 'password': '0' },
        { 'username': '', 'password': '' },
        { 'username': '', 'password': '0' },
        { 'username': '', 'password': '266344' },
        { 'username': '', 'password': '2727378' },
        { 'username': '', 'password': 'secure' },
        { 'username': 'RO', 'password': 'user' },
        { 'username': 'supervisor', 'password': 'PlsChgMe!' },
        { 'username': 'supervisor', 'password': 'PlsChgMe1' },
        { 'username': 'sysadmin', 'password': 'nortel' },
        { 'username': 'system', 'password': 'adminpwd' }
      ];
      break;
    case 'NOVELL':
      # http://open-sez.me/passwd-novell.htm
      logins = [
        { 'username': 'ADMIN', 'password': '' },
        { 'username': 'ADMIN', 'password': 'ADMIN' },
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'admin', 'password': 'novell' },
        { 'username': 'ARCHIVIST', 'password': '' },
        { 'username': 'ARCHIVIST', 'password': 'ARCHIVIST' },
        { 'username': 'BACKUP', 'password': ' ' },
        { 'username': 'BACKUP', 'password': '' },
        { 'username': 'BACKUP', 'password': 'BACKUP' },
        { 'username': 'CHEY_ARCHSVR', 'password': '' },
        { 'username': 'CHEY_ARCHSVR', 'password': 'CHEY_ARCHSVR' },
        { 'username': 'CHEY_ARCHSVR', 'password': 'WONDERLAND' },
        { 'username': 'FAX', 'password': '' },
        { 'username': 'FAX', 'password': 'FAX' },
        { 'username': 'FAXUSER', 'password': '' },
        { 'username': 'FAXUSER', 'password': 'FAXUSER' },
        { 'username': 'FAXWORKS', 'password': '' },
        { 'username': 'FAXWORKS', 'password': 'FAXWORKS' },
        { 'username': 'GATE', 'password': '' },
        { 'username': 'GATEWAY', 'password': '' },
        { 'username': 'GATEWAY', 'password': 'GATEWAY' },
        { 'username': 'GUEST', 'password': '' },
        { 'username': 'guest', 'password': '' },
        { 'username': 'GUEST', 'password': 'GUEST' },
        { 'username': 'GUEST', 'password': 'GUESTGUE' },
        { 'username': 'GUEST', 'password': 'GUESTGUEST' },
        { 'username': 'GUEST', 'password': 'TSEUG' },
        { 'username': 'HPLASER', 'password': '' },
        { 'username': 'HPLASER', 'password': 'HPLASER' },
        { 'username': 'LASER', 'password': '' },
        { 'username': 'LASER', 'password': '' },
        { 'username': 'LASER', 'password': 'LASER' },
        { 'username': 'LASERWRITER', 'password': '' },
        { 'username': 'LASERWRITER', 'password': '' },
        { 'username': 'LASERWRITER', 'password': 'LASERWRITER' },
        { 'username': 'MAIL', 'password': '' },
        { 'username': 'MAIL', 'password': '' },
        { 'username': 'MAIL', 'password': 'MAIL' },
        { 'username': '', 'password': 'cr0wmt 911' },
        { 'username': '', 'password': 'root' },
        { 'username': '', 'password': 'san fran 8' },
        { 'username': 'POST', 'password': '' },
        { 'username': 'POST', 'password': 'POST' },
        { 'username': 'PRINTER', 'password': '' },
        { 'username': 'PRINTER', 'password': 'PRINTER' },
        { 'username': 'PRINT', 'password': '' },
        { 'username': 'PRINT', 'password': 'PRINT' },
        { 'username': 'ROOT', 'password': '' },
        { 'username': 'ROOT', 'password': 'ROOT' },
        { 'username': 'ROUTER', 'password': '' },
        { 'username': 'SABRE', 'password': '' },
        { 'username': 'sadmin', 'password': '' },
        { 'username': 'servlet', 'password': 'manager' },
        { 'username': 'SUPERVISOR', 'password': '' },
        { 'username': 'SUPERVISOR', 'password': 'HARRIS' },
        { 'username': 'SUPERVISOR', 'password': 'NETFRAME' },
        { 'username': 'SUPERVISOR', 'password': 'NF' },
        { 'username': 'SUPERVISOR', 'password': 'NFI' },
        { 'username': 'SUPERVISOR', 'password': 'SUPERVISOR' },
        { 'username': 'SUPERVISOR', 'password': 'SYSTEM' },
        { 'username': 'TEST', 'password': '' },
        { 'username': 'TEST', 'password': 'TEST' },
        { 'username': 'USER_TEMPLATE', 'password': '' },
        { 'username': 'USER_TEMPLATE', 'password': 'USER_TEMPLATE' },
        { 'username': 'WANGTEK', 'password': '' },
        { 'username': 'WANGTEK', 'password': 'WANGTEK' },
        { 'username': 'WINDOWS_PASSTHRU', 'password': '' },
        { 'username': 'WINDOWS_PASSTHRU', 'password': 'WINDOWS_PASSTHRU' },
        { 'username': 'WINSABRE', 'password': 'SABRE' },
        { 'username': 'WINSABRE', 'password': 'WINSABRE' }
      ];
      break;
    case 'OPENBSD':
      logins = [
      ];
      break;
    case 'OPENLINUX':
      # https://www.redhat.com/archives/linux-security/1999-May/msg00004.html
      logins = [
        { 'username': 'help', 'password': '' }
      ];
      break;
    case 'OPENSUSE':
      logins = [
      ];
      break;
    case 'OPENVMS':
      logins = [
      ];
      break;
    case 'ORACLE':
      logins = [
      ];
      break;
    case 'PALO':
      logins = [
      ];
      break;
    case 'PELCOLINUX':
      logins = [
      ];
      break;
    case 'PFSENSE':
      # https://www.netgate.com/docs/pfsense/usermanager/pfsense-default-username-and-password.html
      logins = [
        { 'username': 'admin', 'password': 'pfsense' }
      ];
      break;
    case 'POLYCOM':
      # https://community.polycom.com/t5/VoIP-SIP-Phones/FAQ-What-is-the-Standard-Username-and-Password-for-a-Polycom/td-p/4217
      logins = [
        { 'username': 'Polycom', 'password': '456' }
      ];
      break;
    case 'PRINTRONIX':
      # http://printronix.com/wp-content/uploads/manuals/PTX_UM_PrintNet_Ethernet_P8_257367b.pdf
      logins = [
        { 'username': 'root', 'password': '' } # telnet
      ];
      break;
    case 'PRISMA':
      logins = [
      ];
      break;
    case 'PULSE':
      logins = [
      ];
      break;
    case 'QNX':
      # https://openqnx.com/phpbbforum/viewtopic.php?t=1560
      logins = [
        { 'username': 'root', 'password': '' } 
      ];
      break;
    case 'QUEST':
      # https://support.quest.com/kace-systems-deployment-appliance/kb/111370/default-password-for-the-k2000-appliance
      logins = [
        { 'username': 'admin', 'password': 'admin' }
      ];
      break;
    case 'RARITAN':
      # http://support.raritan.com/dominion-sx/version-3.1.7/quick-setup-guides/qsg-dsxv3-1-7-0j-e.pdf
      logins = [
        { 'username': 'admin', 'password': 'raritan' }
      ];
      break;
    case 'RICOH':
      # https://default-password.info/ricoh/
      logins = [
        { 'username': 'admin', 'password': 'password' },
        { 'username': 'admin', 'password': '' },
        { 'username': 'sysadmin', 'password': 'password' }
      ];
      break;
    case 'ROKU':
      logins = [
      ];
      break;
    case 'RUGGED':
      # https://www.kb.cert.org/vuls/id/889195/
      logins = [
        { 'username': 'factory', 'password': '' } 
      # the password is based on the MAC address and can be easily reverse
      # engineered. But calculation of dynamic default passwords isn't yet
      # supported by this library. Maybe in the future. 
      ];
      break;
    case 'SECUREOS':
      # http://office.it-rostov.ru/files/catalog/asuvp/securos/securos/SecurOS%20-%20v.4.3.2-R3/SecurOS/Manuals/English/securos%20administration%20guide.pdf
      logins = [
        { 'username': 'root', 'password': 'securos2006' },
        # might as well fill in the intervening years, in case there have
        # been new versions released
        { 'username': 'root', 'password': 'securos2007' },
        { 'username': 'root', 'password': 'securos2008' },
        { 'username': 'root', 'password': 'securos2009' },
        { 'username': 'root', 'password': 'securos2010' },
        { 'username': 'root', 'password': 'securos2011' },
        { 'username': 'root', 'password': 'securos2012' },
        { 'username': 'root', 'password': 'securos2013' },
        { 'username': 'root', 'password': 'securos2014' },
        { 'username': 'root', 'password': 'securos2015' },
        { 'username': 'root', 'password': 'securos2016' },
        { 'username': 'root', 'password': 'securos2017' },
        { 'username': 'root', 'password': 'securos2018' },
        { 'username': 'root', 'password': 'securos2019' }
      ];
      break;
    case 'SELESTA':
      logins = [
      ];
      break;
    case 'SHARP':
      logins = [
        { 'username': 'admin', 'password': 'admin' }
      ];
      break;
    case 'SILVER':
      # https://www.silver-peak.com/sites/default/files/userdocs/quickstart_orchestrator_kvm_r7-3_reve_july2015.pdf
      logins = [
        { 'username': 'admin', 'password': 'admin' }
      ];
      break;
    case 'SLACKWARE':
      logins = [
      ];
      break;
    case 'SMC':
      # https://www.edge-core.com/temp/edm/old_downloads/mn/MN_SMC8024L2_Man.pdf
      logins = [
        { 'username': 'admin', 'password': 'smcadmin' }
      ];
      break;
    case 'SOLARIS':
      logins = [
      ];
      break;
    case 'SONICOS':
      # https://www.router-reset.com/default-password-ip-list/SonicWALL
      logins = [
        { 'username': 'admin', 'password': 'password' }
      ];
      break;
    case 'SUSE':
      logins = [
      ];
      break;
    case 'TANDBERG':
      # https://www.cisco.com/c/en/us/support/docs/collaboration-endpoints/ip-video-phone-e20-model/112672-pqa-112672-00.html
      logins = [
        { 'username': 'admin', 'password': '' }
      ];
      break;
    case 'TIMOS':
      # https://learningnetwork.cisco.com/docs/DOC-30272
      # https://vuldb.com/?id.11511
      logins = [
        { 'username': 'admin', 'password': 'admin' }
      ];
      break;
    case 'TOSHIBA':
      # https://mediarealm.com.au/articles/toshiba-topaccess-default-password/
      # https://default-password.info/toshiba/
      logins = [
        { 'username': 'admin', 'password': '123456' },
        { 'username': 'Admin', 'password': '123456' }
      ];
      break;
    case 'TRU64':
      logins = [
      ];
      break;
    case 'UBUNTU':
      # commonly found default login on AWS ubuntu instances
      logins = [
        { 'username': 'ubuntu', 'password': 'ubuntu' }
      ];
      break;
    case 'ULTRIX':
      logins = [
      ];
      break;
    case 'VBRICK':
      logins = [
      ];
      break;
    case 'VIRTUAL':
      logins = [
        { 'username': 'padmin', 'password': '' }
      ];
      break;
    case 'VISUAL':
      # https://www.cleancss.com/router-default/VISUAL_NETWORKS/VISUAL_UPTIME_T1_CSU_DSU
      logins = [
        { 'username': 'admin', 'password': 'visual' }
      ];
      break;
    case 'VMWARE':
      # https://vdr.one/vmware-default-user-passwords/
      logins = [
        { 'username': 'administrator@System-Domain', 'password': '<*>' },
        { 'username': 'admin', 'password': '<*>' },
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'admin', 'password': 'default' },
        { 'username': 'cli', 'password': 'ChangeMe' },
        { 'username': 'administrator', 'password': '<*>' },
        { 'username': 'guest', 'password': '<*>' },
        { 'username': 'root', 'password': '<*>' },
        { 'username': 'root', 'password': '123456' },
        { 'username': 'root', 'password': 'changeme' },
        { 'username': 'root', 'password': 'vmware' },
        { 'username': 'vmware', 'password': '<*>' }
      ];
      break;
    case 'VXWORKS':
      # https://portforward.com/router-password/vxworks.htm
      logins = [
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'guest', 'password': 'guest' }
      ];
      break;
    case 'WESTERMO':
      # https://www.cleancss.com/router-default/Westermo
      logins = [
        { 'username': 'admin', 'password': 'westermo' }
      ];
      break;
    case 'WINDOWS':
      var windows_usernames = [
        'Administrator',
        'Admin',
        'sysadmin',
        'system',
        'user',
        'test'
      ];
      logins = cartesian_product_logins(
          usernames:windows_usernames,
          passwords:base_password_list,
          username_as_password:TRUE);
      break;
    case 'XEROX':
      # http://open-sez.me/passwd-xerox.htm
      logins = [
        { 'username': '11111', 'password': 'x-admin' },
        { 'username': 'Administrator', 'password': 'administ' },
        { 'username': 'Administrator', 'password': 'Fiery.1' },
        { 'username': 'Administrator', 'password': 'fiery.1' },
        { 'username': 'admin', 'password': '' },
        { 'username': 'admin', 'password': '1111' },
        { 'username': 'admin', 'password': '11111' },
        { 'username': 'admin', 'password': '2222' },
        { 'username': 'admin', 'password': '22222' },
        { 'username': 'admin', 'password': 'admin' },
        { 'username': 'admin', 'password': 'sysadm' },
        { 'username': 'admin', 'password': 'x-admin' },
        { 'username': 'HTTP', 'password': 'admin' },
        { 'username': 'NSA', 'password': 'nsa' },
        { 'username': '', 'password': ' ' },
        { 'username': '', 'password': '11111' },
        { 'username': '', 'password': 'admin' },
        { 'username': 'savelogs', 'password': 'crash' }
      ];
      break;
    case 'ZEBRANET':
      # https://default-password.info/zebra/
      logins = [
        { 'username': 'admin', 'password': '1234' }
      ];
      break;
    case 'ZSCALER':
      # https://zscaler.zendesk.com/hc/en-us/article_attachments/202431709/Zscaler_eZ_Agent_Guide.pdf
      logins = [
        'ZSCALER'
      ];
      break;
    case 'ZYXEL':
      # https://www.zyxel.com/support/Zyxel-password-changing-procedure-20161213-v2.pdf
      logins = [
        { 'username': 'admin', 'password': '1234' }
      ];
      break;

    default:
      logins = [
      ];

  }

  ##
  # Elements that consist of a single string, rather than a username/password
  # array, are here converted into the expected type, using the default
  # username that may be supplied as an optional parameter.
  ## 
  var i, num_logins = max_index(logins);
  for (i = 0; i < num_logins; i++)
  {
    var info = logins[i];
    if (typeof(info) == 'string' || typeof(info) == 'data')
    {
      info = { 'username': default_username, 'password': info };
      logins[i] = info;
    }
  }
  
  # If we have fewer than max_logins in our list, then add as 
  # many additional logins from base_list as needed.
  var next = num_logins;
  var to_add = max_logins - next;
  if (to_add > max_index(base_list))
    to_add = max_index(base_list);
  var p, seen = make_array();
  foreach (p in logins) 
  {
    seen[serialize(p)] = TRUE;
  }
  for (i = 0; i < to_add; i++)
  {
    if (!seen[serialize(base_list[i])]) 
    {
      logins[next] = base_list[i]; 
      next ++;
    }
  }
  # NB: avoid duplicates


  return logins;
}


##
# Given a login array, extract the password.
##
function get_password() { return _FCT_ANON_ARGS[0]['password']; }

##
# Given a login array, extract the username.
##
function get_username() { return _FCT_ANON_ARGS[0]['username']; }

function map_to_uniq(f)
{
  var non_uniq = collib::map(f:f, _FCT_ANON_ARGS[0]);
  var set = new('collib::set', non_uniq);
  return set.to_list();
}

function get_pci_password_list(default_username, platform)
{
  return map_to_uniq(f:@get_password, 
      get_pci_login_list(default_username:default_username, platform:platform));
}

function get_pci_username_list(default_username, platform)
{ 
  return map_to_uniq(f:@get_username, 
      get_pci_login_list(default_username:default_username, platform:platform));
}

