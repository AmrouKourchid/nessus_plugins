#TRUSTED 74805ab6e9c8f9f02b6e0961aa46c7a87d70c66dcb8bd5fc98c7057180948b820ab952a190c0de40afe121de5fe1cb719a989c2cb202d0b98f0800b0fcf8dfdef7e2eb26de637fe7d705771be31d9e18d6b321a8fe87046f7dbca6cfb693a7420f2490b2853981517523d6273eb5730ebd526a6f1a291b08519aa062a42f07b54b8c4688c9670831409c3e0a901a9f7409faac94a6d7712492db09f2da3defa352813f8aef92f3b81c0324420e6f21ec2dbc5f2652f870443ead413403fb9f8347bcce0b80a7978675e386ff2dc5232d015f151a8ac622e8c7965d58348447dca0ecec4cd6ce49d8618a7d407122a70825790c51f8875e05778e98792df4ddf42ea63f8d962a02854ece20d986622b7b809f1eb72d40cb7eea25a4be34422ba7200a0ab938c77e29f16a4904d1df7c79039a9d75500bdc055e8a38a2e49e38d6dcfc111bf0868594c2caf094c56a3d9936e4e99c3e0a8f57edab79448d79ca60d6aa54a9618dd839559f380e0d4ece36489cf7470d32478d659ebd904afdaff396cd2bdb3e73768f14e6bea3f51a1283627d89a4f824954092fb3f17d6c7c8c6c9a4a0058e107397b405c9a9b1611f857b4e0e29744fea91681d655b9b3cff286b0ecbd6175642775c3ea9425ac42ad705161046cd63ebebd7193eb821955d3696b43ab1b9790bdf4893abce4933bcc424e609bfe64052af78ab3b3d00e1452c
#TRUST-RSA-SHA256 94da0f16a948db51501c759d0764b9270700a0a3217ed9190c03d01f6a3b2adc6ed997201aac618f14185c8104ca846c51e309d378e65b0aff103424cfa6214632cfd986627682f02f0f8f67762b16c4bae11b6e012614ae5df1e13245c78fffff5686186bbc48be9b072dabc34f514db1ba2566ba50d817b42c869872bdb955e3ec91bf268b3763c4e1df80fba5c846fc0edac8f50861e3ca3c227edc95ee38157e3195f562ec32eed93fa153c0203ef125a655540e5f54e7400a758d4df6f1cc789a8d0126838751582b57176e2d59cf6d081624d81ff07c12d02d9c9c4020239e09739809fe12902487785950de73d75bf4551e47bde19b700fbe28c6fdbb7f155117c637b1e8b1e9fc8dfc0967df3434dbfba1a78db06dcbdcb5969bb33de5332332e16500ffd9a1f9daeca81d98c48123b7d377d5f68e94de311d9c611d027f1db92216c97882dd662eb3cbb990d7f9fd71443bfb8d67e0e5a5d7c4e0e9aeb29cb00d3ff53db36bc9872e53477c6f08585554b0a983337bdb928f5cb58509da191b447e5ef2185dfbef8f73d5f0279e8592da98ce474eebd8d9073eebc791ab435af638dd39054c0f4c6316521988ce8a7de6b2104e912b562bc7f553b022f866b2d213c177c2d5d3d2de412333f19d6fe741b9b84d9f58f0ccab48aa109463ab3dd57064ad52379f4fe2459e3b94ac34e964557ff22e91d838be3e470a
#%NASL_MIN_LEVEL 80900

##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232585);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/11");

  script_name(english:"Windows Registry Enumerated Software Report");

  script_set_attribute(attribute:"synopsis", value:"Reports details about software enumerated using the registry");
  script_set_attribute(attribute:"description", value:"Reports details about software enumerated using the registry");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/11");

  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_END2);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('json2.inc');
include('win_uninstall.inc');
include('structured_data.inc');

exit(0, "This plugin is currently disabled");

var cached_software = win_uninstall::get_detected_cache();

var software = win_uninstall::get_enumerated_software(fields:['DisplayName', 'Publisher', 'DisplayVersion', 'InstallLocation']);

var installed_software = new structured_data_installed_sw();

foreach var install (keys(software))
{
  if(isnull(software[install]['DisplayName']) || 
     cached_software[tolower(str_replace(string:install, find:'/', replace:'\\'))])
  {
    continue;
  }

  var data = {
    string_id: hexstr(SHA256(tolower(str_replace(string:install, find:'/', replace:'\\') + software[install]['DisplayName']))),
    app_name: 'RegistryUninstall:' + software[install]['DisplayName'],
    product: software[install]['DisplayName'],
    vendor: 'Unknown'
  };

  var value = software[install]['Publisher'];
  if(!empty_or_null(value))
  {
    data['vendor'] = value;
  }

  value = software[install]['DisplayVersion'];
  if(!empty_or_null(value))
  {
    data['version'] = value;
  }

  value = software[install]['InstallLocation'];
  if(!empty_or_null(value))
  {
    data['path'] = value;
  }

  installed_software.append('installs', data);
}

installed_software.report_internal();
security_report_v4(port:0, extra:'Successfully retrieved and stored Windows registry enumerated software.', severity:SECURITY_NOTE);