#TRUSTED 1ab69b51dfab8ca207f97504a699f4fa70a3666a45fc4f97db65fd8f844f7b1aece164bba4dbe30396af6c714b40e2e3909e822cda26b0f767020816d044cbfbeb03756e7ccb91ae2c9a968d21ee03228e7cb611a2a1876f48cfaef0a94fc302cf5ab27246f21f3803fbdb7682bb57428d619806f7d60bc5b2e48192cae4da888df8894c4d37353fbc1654930e1ee3a5166f2614d1d14e00cd66a1117b4b6ce59a09e078245f4029587b51d327af5f301dad4828f7bfe68a4872f3b186cffebdc091d0ea843982ef57e31c5ab2355adffa054aa555e851502cc9d7bc7cd37af88d30dcdef700d736e7fad44dde9b582fd1db548c0a9c0eb46fe8cbd123e3aed606a1e9a5c9ad0cac87e0b9c25416198b2f57cadc7bfddfcdb6a4a07c3188db9a48a650e25bd28ca10b0c3227cfc22e936a41410fd3ae3d68220513038ad32c0f266306f98a7003f97453e26206155e6e9702a651865b68c0315441ee9de81d87e2b4b608d330768598ab839b12115e82906833b8bff15f1750ecac196e25cda7afe4c1c0a7af90833a2ee8995c98755a81f555e1c32594b8ce08cc3c520f9e5afc03bea3a95b2c673aa6c358f72c2ab847d89d08b02fdee750c250dbdc2e197412468b7c4893dbee697a8717d5dee080b021cf79a27bb24bce66c6362ecef2e0eb37513ca73ccf7559525a2e78e82fe6cf011fac11e16d88d802b8b1574b090f
#TRUST-RSA-SHA256 3dda195a39178090e8135a0d9744c921868dfc623af26884bb1a884bdfb97ab2370ff85b389ec415ab4b310ce836bc9598d9edfd678e46335bccc4c673f053f4241fda69425527286709610cf3c0a09237dad912a14a6ae8c930cbe2b29885a377d54f2f18ec57662717862fa90f425a076e12ac8764d094f980dbef67c02d39397c269e7f1010ff2d9397409db92ed742c5731acbd5ef9910a5d8eb7cd9f9afb31345b18502d31c228b636d2cce4157efa378e2d87a7e52fe442d6321b54400156e1bfd8c4e78a370fce7ede4c721693d89309fe13c5c19fef79193e6cc9f2809e1fc23a1657adb9db0c88e6b234e1cf0b7a334f85557b09c52a063c9270501151fcbfcfbeee2a8f9fe109183ef58a509ba449746cc4606c450496e5c5bab33da8997040c974d5c182317604e6ad9da33dfa9999b693938f32d6e05e3f4fe4ccc91f807fab1d648f5d75f43c1d7c8d408cba45c3538b16e3cbb92eae0c76358f618aacdba722888ebd13046d1b513d872b863e2b5ffffb0a7042b9d3c73d4323e0fbde792c7a87517ad77cfa1f9b2580e61d7088420c6645be31d56af52ae4cf9a83f5fd4d87833218154735e13551f120312513c90832a9221f0ab8d435e052cc44039924992b4585bd4821e15ded71ff491a6045bbbf9a9e5e255aeb3fcb5054c681101a92c1fee23ce82efb54c7566869bb88b9684c0670b3a9c6b59122c
###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# Revision: 1.3
#
###

include('asset_registration.inc');
include('compat_shared.inc');
include('cpes.inc');
include('debug.inc');
include('install_func.inc');
include('string.inc');
include('structured_data.inc');
include('validate.inc');

##
# Registers the hardware device.
#
# @param  [type:str]              The fingerprinting type used to determine the hardware device (local, remote, or combined).
# @param  [method:str]            The fingerprinting method used to determine the hardware device.
# @param  [confidence:int]        The confidence level of the fingerprinting method used to determine the hardware device.
#
# @param  [vendor:str]            Describes person or organization that manufactured or created the product.
# @param  [product:str]           Describes the most common and recognizable title or name of the hardware device.
#
# @param  [protocol:str]          The protocol used for detecton, only used with 'remote' type (optional).
# @param  [port:int]              The port used for detection, only used with 'remote' type (optional).
#
# @param  [sw_edition:str]        Describes how the product is tailored to a particular market or class of end users (e.g. Home, Professional, Enterprise) (optional).
# @param  [version:str]           The version of the product to be used for comparison (optional).
# @param  [display_version:str]   The more user friendly product version, including a release codename (optional).
# @param  [update:str]            Describes the particular update, service pack, or point release of the product (optional).
# @param  [full_name:str]         Full name of the detected operating system that is most recognizable (optional).
#
# @param  [language:str]          The language tags, as defined in RFC5646, describing the supported language of the hardware device (optional).
# @param  [target_hw:str]         Describes the instruction set architecture of the app (e.g. x86, x64) (optional).
# @param  [cpe:str]               The CPEv2.2 ID assigned to the hardware device.
# @param  [cpe_part:str]          The type of product, used for CPE strings ('a', 'h', 'o'). Defaults to 'h' (optional).
#
# @param  [category:str]          The general classification of the hardware device.
# @param  [product_number:str]    The identifier assigned to a specific product by the vendor (optional).
# @param  [serial_number:str]     The unique identifier assigned to the product by the vendor (optional).
# @param  [hardware_uuid:str]     The universally unique identifier assigned to the product by the vendor (optional).
# @param  [firmware_version:str]  The firmware version installed on the product (optional).
#
# @param  [extra:array]           Extra data that is does not fix any parameters. Values may be strings, integers or lists (optional).
# @param  [extra_no_report:array] Extra data that is does not fit any other parameter but not included in the report. Values may be strings, ints or lists (optional).
# @param  [priority:int]          Priority of this install which determines if it should overwrite a duplicate (optional).
#
# @return IF_OK if successful
#         IF_ERROR otherwise
##
function register_hardware(vendor, product, type, method, confidence, protocol, port, 
  full_name, sw_edition, version, display_version, update, language, target_sw, target_hw, other, cpe, cpe_part,
  category, product_number, serial_number, hardware_uuid, firmware_version, extra, extra_no_report, priority)
{
  var registrar = new asset_registration::registrar(hardware_registration::asset_type);

  if (empty_or_null(cpe_part))
    cpe_part = 'h';

  registrar.set_base_attributes(
    type             : type,
    method           : method,
    confidence       : confidence,
    protocol         : protocol,
    port             : port,

    category         : category,
    full_name        : full_name,
    vendor           : vendor,
    product          : product,
    version          : version,
    display_version  : display_version,

    update           : update,
    language         : language,
    sw_edition       : sw_edition,
    target_hw        : target_hw,

    cpe              : cpe,
    cpe_part         : cpe_part,

    extra            : extra,
    extra_no_report  : extra_no_report
  );

  registrar.set_extended_attributes({
    product_number   : product_number,
    serial_number    : serial_number,
    hardware_uuid    : hardware_uuid,
    firmware_version : firmware_version
  });

  # Commenting out until we have confirmation that this addition will not cause issues.
  #if (serial_number)
  #{
  #  var snc = new structured_data_asset_identifier();
  #  var id_data = {
  #    identifier_source : vendor + 'SerialNumber',
  #    identifier_value  : value
  #  };
  #  snc.append('identifier', id_data);
  #  snc.report_internal();
  #}

  return registrar.register_asset(kb_root: hardware_registration::kb_root);
}

##
# Reports detected hardware device(s).
#
# @param  [protocol:str]  The protocol used for detecton, only used with 'remote' type (optional).
# @param  [port:int]      The port used for detection, only used with 'remote' type (optional).
# @param  [extra:str]     Additional data to be appended to report (optional).
# @param  [attributes:array] Hardware array returned from get_hardware(). Used for reporting outside of plugin with register_hardware(). (optional) 
#
# @return true if successful
#         NULL if an error occurred
##
function report_hardware(protocol, port, extra, attributes)
{
  var reporter = new asset_registration::reporter(hardware_registration::asset_type);

  reporter.format(
    order         : hardware_registration::report_order,
    display_names : hardware_registration::report_display_names
  );
  
  if (attributes)
    InstallReport[hardware_registration::asset_type] = reporter.add_install_to_report(attributes:attributes);

  return reporter.report_installs(protocol:protocol, port:port, extra:extra);
}


##
# Get the detected hardware device(s) only returning device info only if the optional specified arguments match.
#
# @param  [type:str]     The fingerprinting type used to determine the hardware device (local, remote, or combined) (optional).
# @param  [category:str] The general classification of the hardware device.
# @param  [method:str]   The fingerprinting method used to determine the hardware device (optional).
#
# @param  [vendor:str]   Describes person or organization that manufactured or created the product (optional).
# @param  [product:str]  Describes the most common and recognizable title or name of the hardware device (optional).
#
# @param  [release:str]    The release of the product when the vendor provides one (optional).
# @param  [full_name:str]  Full name of the detected operating system that is most recognizable (e.g. vendor + product + release) (optional).
#
# @param  [all:bool]  Return all detected hardware devices that match the specified arguments (optional / default: false).
# @param  [exit_if_not_found:bool] exits if the hardware device is not found (default:true) (optional)
#
# @remark if multiple hardware devices are found, the hardware devices with the highest confidence will be returned
#
# @return array of the hardware device info (see register_hardware() for values) if successful
#         if the 'all' flag is set, a list of arrays of the hardware device info (see register_hardware() for values) if successful
#         NULL otherwise
##
function get_hardware(type, category, method, vendor, product, release, full_name, all, exit_if_not_found)
{
  var retriever = new asset_registration::retriever(hardware_registration::kb_root);
  
  if (all)
    return retriever.get_assets(type:type, category:category, method:method, vendor:vendor, product:product, full_name:full_name, exit_if_not_found:exit_if_not_found);
  else
    return retriever.get_asset(type:type, category:category, method:method, vendor:vendor, product:product, full_name:full_name, exit_if_not_found:exit_if_not_found);
}


##
# Get the detected hardware device(s) info based on the CPE attributes only returning device info only if the optional specified arguments match.
#
# @param  [type:str]        The fingerprinting type used to determine the hardware device (local, remote, or combined).
# @param  [category:str]    The general classification of the hardware device.
# @param  [method:str]      The fingerprinting method used to determine the hardware device.
#
# @param  [part:str]        Type of the product ('a' for applications, 'o' for operating systems, 'h' for hardware)
# @param  [vendor:str]      Describes person or organization that manufactured or created the product.
# @param  [product:str]     Describes the most common and recognizable title or name of the product.
# @param  [version:str]     Describes the particular version of the product.
# @param  [update:str]      Describes the particular update, service pack, or point release of the product.
# @param  [language:str]    [RFC5646] language tag describing the supported language of the product.
# @param  [sw_edition:str]  Describes how the product is tailored to a particular market or class of end users
# @param  [target_sw:str]   Describes the software environment of the app (ie: OS)
# @param  [target_hw:str]   Describes the instruction set architecture of the app (ie: x86, x64)
# @param  [other:str]       Additional CPE 2.3 info
#
# @param  [exit_if_not_found:bool] exits if the hardware device is not found (default:true) (optional)
#
# @remark Example usage: var cpe = get_hardware_cpe(part:'h', vendor:'cisco', product:'wap2000', type:'local');
# @remark Wildcards are allowed in the value since the match() function is used
#
# @return array of the hardware device (see register_hardware() for values) if successful
#         NULL otherwise
##
function get_hardware_cpe(type, category, method, part, vendor, product, version, update, language, sw_edition,
                          target_sw, target_hw, other, exit_if_not_found)
{
  var retriever = new asset_registration::retriever(hardware_registration::kb_root);

  if (empty_or_null(part))
    part = 'h';

  return retriever.get_cpe(
    type       : type,
    category   : category,
    method     : method,

    part       : part,
    vendor     : vendor,
    product    : product,
    version    : version,
    update     : update,
    language   : language,
    sw_edition : sw_edition,
    target_sw  : target_sw,
    target_hw  : target_hw,
    other      : other,

    exit_if_not_found : exit_if_not_found
  );
}


namespace hardware_registration
{
  var asset_type = 'hardware-device';
  var kb_root = 'installed_hw';

  var report_order = [
    'full_name', 'vendor', 'product', 'release', 'sw_edition', 'version', 'display_version',
    'category', 'product_number', 'serial_number', 'hardware_uuid', 'firmware_version',
    'language', 'target_hw', 'cpe:v22', 'cpe:v23', 'type', 'method', 'confidence', 'protocol', 'port'
  ];

  var report_display_names = {
    full_name        : 'Hardware Device',
    product_number   : 'Product Number',
    serial_number    : 'Serial Number',
    hardware_uuid    : 'Hardware UUID',
    firmware_version : 'Firmware Version',
  };
}
