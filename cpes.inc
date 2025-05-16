#TRUSTED 7ed1d656e2dcfad38efeffa94598af614ad34f7b406abe3718129ae4cda9b685baa0695c4cf29104e1c8c938a0db3a10b057e6ad9dda09b01ff2e5ee8873a1be653d636ac4e7eab46435f8fcbdad109a06182f0dd40d63e9c69d1da6f834bcc2ef9049de7a5e5fdc712531f6e182e14c0aa15b3b22046f1144184a818f0e6ea49d616088f7cedf5dbde7ad63ca5d0740fd7e896ec641c13a8be48a77e9c64015a372ead03831e4ae3ea1d9d80f6833ef53288877d2be0f96a1c47940b84af6fa843d16cf6a16e3df421a171e89ca3a346bdbb4774bcffd4d7050fd30f7cfcabaeeec595368298b34d89d62b6e57eccc773e5048fea9c2fc3af70e69a5b4adc5bf6c68ef924e3d0892468cd70a63ae61881990f15ac9761d63ba825db1843866d9f93aae7d9b50acfebf041ec11008ca2671cf6a46973adac452064f12f049427235bd73e19c0ff06be5fc3ce398afbe754c4a7421b49b7cbc7ba5bf173971f0277e94bbbf792f994df26b2ddafe531a6d41393e6655650ff1fab8774d325e11784fa3128f7e91a47a92a06c17d5adc295029a8bd210c1ef2d921db5df79bc688bf92bead774bc869c37d1834149775beef886f788e7c663967a69fec82ce5b8a0e51f38e4865519a007d27a308c575236360e505b3ac84e0fa19fb0f7c8446b368bb3c4b059e51d510bb2e2115785f42142aa49f6a1409f6cd2201aefc0c211d
#TRUST-RSA-SHA256 ace410affeda14b520fb9ca2065b6bbfd6d7b129bd657c5592ce68ad9082a9df4fcad09ab08ee54ac2c58af47be81b61fbfef877db83e1b4f281436b48a48a154e5e03697eff93aec06cf80edac83a6799965ab946d425d4f96af3f310437396b91fb47a51f32a5f7b6ed0d60ef327add743dd217b04fb1348a467f49f77c2b360d560f22527fe004c81d605b222f5314ec45c34075dac291cc3b8f4c637e0ba82dd2de4fb499b493a47a0ba9808e81328e2671e1878c8702df7772b27a190065a31efbb1e841f301501a55a7899fcf4394bbd85e1010720ed3f26024917e7ee34bdeaad566376ae619689da02a266f5c75392c56d2d3ad7b3d4d36981f83f89affdbfda9b4d8c9b18730eed3802f62d362b60586c73fb423340834eb44fe27931aaa7dcd75aa247c34c7b2e3a8cfdbe7bfda57f4d183d301a0ba00de6491b08a054fcf0af18d57aea234cbbad2ae80be7e9f64c24382e5dae9de8c91536c3cf8ef47b1d9ee4775b117c34ff4f8175dbc6f93cac31a044e6c34fe32cc00426a4d9786c1a716931320fec470c8f1aeefe5b981293ec890f6c5f2129e46308bd00cc200fd0d244db305d20a547e663b9b69f2c173a36a3ea0cf4af0f79adde241c0ac97c122945a8b037f1d0826edb869f941405443661e503f675ce04ed36f4c284390c271b31270b7cb224e305da13cbbd1fb417b0196c106d117fa157e90d0f
###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# Revision: 1.4
#
###

include('compat_shared.inc');
include('debug.inc');
include('install_func.inc');
include('validate.inc');

namespace cpes
{

  var attributes_order = [
    'part', 'vendor', 'product', 'version', 'update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other'
  ];

  var checker = {
    data : new validate::type_checker(),
  };

  var unreserved_chars = '[a-z0-9_.*~%-]';


  ##
  # Compare list of specific CPE attributes arrays to the full CPE attributes
  #
  # @param  [installed_cpe_attributes:array]  CPE URI broken down into CPE attributes
  # @param  [query_attributes_list:list]      List of arrays of query attributes to match against
  #
  # @remark Recommend using cpe_decode() on the CPE URI for the CPE attributes
  # 
  # @return true if one of the query attributes arrays matches; false if not; NULL is an error occurred 
  ##
  function compare_attributes_list(installed_cpe_attributes, query_attributes_list)
  {
    # Argument check
    var checks, validation;
    checks = [
      { argname: 'installed_cpe_attributes', arg: installed_cpe_attributes, checker: checker.data.array },
      { argname: 'query_attributes_list',    arg: query_attributes_list,    checker: checker.data.list  }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    # Comparison of CPE attributes
    var results;

    for (var query_attributes of query_attributes_list)
    {
      results = compare_attributes(installed_cpe_attributes: installed_cpe_attributes, query_attributes: query_attributes);

      if (results.matched)
        return true;
    }

    return false;
  }


  ##
  # Compare specific CPE attributes to the full CPE attributes
  #
  # @param  [installed_cpe_attributes:array]  CPE URI broken down into CPE attributes
  # @param  [query_attributes:array]          Query attributes to match against
  #
  # @remark Recommend using cpe_decode() on the CPE URI for the CPE attributes
  # 
  # @return array with key 'matched' set to true if all attributes matched, false otherwise.
  #         Also, a 'mismatch' key with the attributes that did not match
  ##
  function compare_attributes(installed_cpe_attributes, query_attributes)
  {
    # Argument check
    var checks, validation;
    checks = [
      { argname: 'installed_cpe_attributes', arg: installed_cpe_attributes, checker: checker.data.array },
      { argname: 'query_attributes',         arg: query_attributes,         checker: checker.data.array }
    ];
  
    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    # Compare attributes
    var results = {};
    var attribute, pattern;

    for (var query_attribute in query_attributes)
    {
      pattern = query_attributes[query_attribute];
      pattern = standardize_cpe(cpe:pattern);

      # Since 'edition' is deprecated, use it as an alias to 'sw_edition'
      if (query_attribute == 'edition')
        query_attribute = 'sw_edition';

      attribute = installed_cpe_attributes[query_attribute];
      attribute = standardize_cpe(cpe:attribute);

      # Use match() here to support wildcards similar to WFN matching
      if (
        !match(string:attribute, pattern:pattern)
      )
      {
        results.matched = false;

        if (isnull(results.mismatch)) results.mismatch = [];
        append_element(var:results.mismatch, value:query_attributes[query_attribute]);
      }
    }

    if (isnull(results.matched))
      results.matched = true;

    return results;
  }


  ##
  # Encode reserved characters (section 6.1.2.1.2)
  #  - Unreserved characters: ALPHA / DIGIT / "-" / "." / "_"
  #
  # @param  [cpe:str]  CPE URI to process
  #
  # @return CPE URI with encoded characters (if any)
  #         NULL if an error occurred
  ##
  function encode_reserved_chars(cpe)
  {
    # Argument check
    var checks, validation;
    checks = [
      { argname: 'cpe', arg: cpe, checker: checker.data.str }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    # Process CPE
    var attributes, attribute, attribute_value;
    var processed_attributes, processed_attribute, processed_char, processed_cpe;

    # Map attributes names to values
    attributes = split(cpe, sep:':', keep:FALSE);

    processed_attributes = [];
    
    for (var index in attributes)
    {
      attribute = attributes[index];
      processed_attribute = NULL;

      # Special handling:
      #  - part attribute in CPEv2.2 (e.g. '/o')
      #  - empty attribute
      if (
        index == 1 && attribute =~ '/[aoh]' ||
        empty_or_null(attribute)
      )
      {
        append_element(var:processed_attributes, value:attribute);
        continue;
      }
    
      # Process each character (one at a time)
      for (var i=0; i < strlen(attribute); i++)
      {
        processed_char = attribute[i];
    
        # Character is reserved - percent encode the character (e.g. ',' becomes '%2c')
        if (attribute[i] !~ unreserved_chars)
          processed_char = '%' + hexstr(attribute[i]);
    
        processed_attribute += processed_char;
      }
    
      append_element(var:processed_attributes, value:processed_attribute);
    }
    
    processed_cpe = strjoin(list:processed_attributes, separator:':');

    return processed_cpe;
  }

  ##
  # Construct all versions of the CPEs based on the specified information.
  #
  # @param  [base_cpe:str]    The base CPEv2.2 ID assigned to the hardware device.
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
  # @return array of CPEs with the keys 'v22', 'v22C', and 'v23' and the relevant constructed CPE string as the value
  ##
  function construct_cpes(base_cpe, part, vendor, product, version, update, language, sw_edition, target_sw, target_hw, other)
  {
    # Construct the CPEs based on the data provided
    var cpe_ver, constructed_cpe, cpe_parts, cpe_attributes;

    var constructed_cpes = {};
    var cpe_vers = ['22', '22C', '23'];
  
    foreach cpe_ver (cpe_vers)
    {
      constructed_cpe = construct_cpe(

        cpe_ver    : cpe_ver,
        base_cpe   : base_cpe,
        part       : part,
  
        vendor     : vendor,
        product    : product,
        version    : version,
        update     : update,
  
        edition    : '*',
        language   : language,
        sw_edition : sw_edition,
        target_sw  : target_sw,
        target_hw  : target_hw,
        other      : other
      );
  
      if (constructed_cpe[0] != IF_OK)
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Failed to construct CPEv' + cpe_ver);
        continue;
      }
  
      constructed_cpe = standardize_cpe(cpe:constructed_cpe[1]);
      constructed_cpe = cpes::encode_reserved_chars(cpe:constructed_cpe);
  
      # Prepend 'v' for better array access
      cpe_ver = 'v' + cpe_ver;
  
      constructed_cpes[cpe_ver] = constructed_cpe;
    }

    return constructed_cpes;
  }
}
