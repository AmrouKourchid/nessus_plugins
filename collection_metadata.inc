#TRUSTED 08df6c978b4ebd38338e4bff6b607c228c77e333a4f547a8167d854cbf55c126af9847fe2f05ca959c6e9bdcc6199bcc15e517bc1b852c075cfd3feb3a53c9413f16eb9f5f4ca0ed8906ab655fc6efef18529386d8ea53aa4789f07193bbcbc5881dce752ca2362bb1f67140984630d29de2a7ee8b016a32af4617b4bb8cbd0b3c00fdf012a39730be7cb02745144657d839bc2e7b9f23129ac1db5c8deda1cc7c942b1767b5c884e4649b71319b68200baf2d32e227edae13d11b2f88c2cf971728561e3487df1c00425c6ac5cdc52d8ed51afd0a1febb99396384137ab0c850ecda0d56bce2bdfbdfae15e5eaede21ab7b7f1a0b1fc5030a6c7f4a841c3c2fe0310035adb4a7949b91ba9cbcaf593543a98648251e030ad038f1d81e41a335d0d69f670b74d3c4c4dce44a44d5bf2a7c8f1745cfb308fc00385b28a73f26d2e56fbc961085b073323ee20f41c7ce0e49dee6bf1a7558f9a80a9338c91d5810cfd210509bf21375f9d4c9a82545d28fab0ffe3bef4dcaa92854daca47b117dcdf2ed65f2e736d46332a46c603fcc02a21f1fd48545c967c72d93518f74d4bdc3169cc037f3568373117b647da6a4ca719ec09add74c4e2a3c1cb2f252725f5950a4379f6830ea8f2b0c5b4f16e5e910b2981abcbd6c5f4730c88672a74c4459f06d41069ad737cc5f216f8590a95a515545892696bde43dd3cce9b8289e6c8b
#TRUST-RSA-SHA256 4cd4c544c22160f73980620c3d19cd2b100ec0ed8a4e4d518ba823ffd6397c42c7396669b37732a11ddc6862be8fb82c0dd9fed7a20d2f7b7818522dde1fc3c493d566ad986f8b741482aaa45ca2b40ea525ba263b8a0eb624f656305151502760c15ec694124e46917bb19a6aa7927b1bb6af2feea74c60ce9760cb578a7ea6cc1690703f84ada777397b2edcece417235c7fb923e5de79e55eb9667ee7773c7584a54ac4fe93e1e2939bf878ff2c912e1e13f4cc48b00889cf5a79985063f4d4bba51cf8622c686edcac7ea843fb8430d0be274f1a07a105e11c4fd9754dfa2eebdb2a46134f55ea531a15fc00f4b35a4be61774b2ea44ea6802cb48cd4431b62b605a69ca826b1760e01a73002b6d5c94b7402bacdaff7f1c2bf0a144d14cde4c13d4237a1d1e1172823a51133bf7d9926f479c1e7a48342a26bc8a5686533ed49c8b1d7b95d19da3990ba7f629e2ad7858a0a31b3bc3af8c82a873aea4ae382953569ddfb25d68cc5a38f1bfa99b0cbe658f364be0a3a19e6d792306dcf6696a5a3c2223ba285909ee6528bef3188cd05ff82371532f49f248eccc02e872798f33a669dc98a030bd54222e2205207bccac1a2a261dd6d7af90becb8632f2c5425899e964d820e61c22077dfd408c0bfe504dd58d6749119d7025ae69a60f8fa7386a04c0bf41070943fab41aa2ff1c84ac922ebfa94748a5b659375088ec

###
#
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# collection_metadata.inc
#
# Revision: 1.02
#
###

include("json2.inc");
include("compat_shared.inc");

namespace collection_metadata
{
  object collection_metadata
  {
    var collect_methods = [];
    var metadata = {};

    ##
    # Track the data about the version file used for a detection
    #
    # @param [path:string] Absolute path of the file used for detection
    # @param [size:int] Size of file in bytes
    # @param [last_modified:int] Unix timestamp of the file's last modification
    #
    # @return `true` on success, `false` on invalid input or failure
    ##
    public function set_version_file(path, size, last_modified)
    {
      if(empty_or_null(path)) return false;
      if(!isnull(size) && typeof_ex(size) != 'int') size = NULL;
      if(!isnull(last_modified) && typeof_ex(last_modified) != 'int') last_modified = NULL;

      this.metadata['version_file'] = {
        path: path,
        size: size,
        last_modified: last_modified
      };

      return true;
    }

    ##
    # Clear any metadata registered with the provided name
    #
    # @param [name:string] the metadata name
    #
    # @return NULL
    ##
    protected function clear_metadata(name) {
        if (!empty_or_null(this.metadata[name]))
        {
            delete_element(var:this.metadata, idx:name);
            var to_remove = NULL;
            repeat {
              to_remove = NULL;
              for(var i = 0; i < max_index(this.collect_methods); i++) {
                  var input = this.collect_methods[i]['input'];
                  if (empty_or_null(input)) continue;
                  var input_value = input['value'];
                  if (input_value == name)
                  {
                      to_remove = i;
                      break;
                  }

              }
              if (!isnull(to_remove))
                  delete_element(var:this.collect_methods, idx:to_remove);

            } until(isnull(to_remove));
        }
    }

    ##
    # Clear any metadata registered with `version_file`
    #
    # @return NULL
    ##
    public function clear_version_file_info() {
        clear_metadata(name:"version_file");
    }

    ##
    # Return the serialized `version_file` data.
    #
    # @return array matching the `version_file` object from `tenb_fa_normalized_inventory_schema.json`,
    #         or NULL if no version files have been recorded
    ##
    public function get_serialized_version_file()
    {
      if(!empty_or_null(this.metadata['version_file']))
      {
        return serialize(this.metadata['version_file']);
      }

      return NULL;
    }

    ##
    # Register one or more collection method items for the provided property.
    #
    # @param [property:string] Property name this collection method is for (e.g. "version")
    # @param [methods:list] List of methods (array items matching the `collect_methods.methods` items
    #                       from `tenb_fa_normalized_inventory_schema.json`)
    #
    # @remark This is protected to encourage the public interface of the object to use a higher level of abstraction.
    #         If this is not possible, or makes for a worse interface, this decision _may_ be changed.
    #
    # @return `true` if the method was added, `false` on invalid input
    ##
    protected function add_collect_method(property, methods)
    {
      if(empty_or_null(property) ||
          (typeof_ex(property) != 'data' && typeof_ex(property) != 'string'))
      {
        return false;
      }

      if(empty_or_null(methods) || typeof_ex(methods) != 'list')
      {
        return false;
      }

      append_element(var: this.collect_methods, value: {property: property, methods: methods});

      return true;
    }

    ##
    # Register an array matching the `collect_methods.methods` items from `tenb_fa_normalized_inventory_schema.json`
    #
    # @param [input_value:string] Name of the property containing the file path (e.g. "version_file")
    # @param [regex:string] Regex to extract from the file
    #
    # @remark This is protected to encourage the public interface of the object to use a higher level of abstraction.
    #         If this is not possible, or makes for a worse interface, this decision _may_ be changed.
    #
    # @return NASL array representing a `file_content` method, or NULL on invalid input
    ##
    protected function create_file_content_method(input_value, regex)
    {
      if(empty_or_null(input_value) || empty_or_null(regex))
      {
        return NULL;
      }

      return {
        name: "file_content",
        input: {
          type: "filePath",
          value_type: "properties-reference",
          value: input_value
        },
        args: {
          match: regex
        }
      };
    }

    ##
    # Return the serialized `collect_methods` data
    #
    # @return array matching the `collect_methods` object from `tenb_fa_normalized_inventory_schema.json`,
    #         or NULL if no collect methods have been recorded
    ##
    public function get_serialized_collect_methods()
    {
      if(empty_or_null(this.collect_methods))
      {
        return NULL;
      }

      return serialize(this.collect_methods);
    }

    ##
    # Register `collect_method` and `version_file` items for a file-regex based detection.
    #
    # @param [path:string] Absolute path of the file used for detection
    # @param [size:int] Size of file in bytes
    # @param [last_modified:int] Unix timestamp of the file's last modification
    # @param [regex:string] Regex to extract from the file
    #
    # @return `true` on success, and `false` on invalid input or failure
    ##
    public function add_version_file_with_regex_helper(path, size, last_modified, regex)
    {
      this.set_version_file(path: path, size: size, last_modified: last_modified);
      var method = this.create_file_content_method(input_value:'version_file', regex:regex);
      if(isnull(method)) return false;
      if(this.add_collect_method(property:'version', methods:[method]))
        return true;
      
      return false;
    }
  }
}
