# Copyright (c) 2015 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import unicode_literals
import json
import re

import tempest_lib.base


# class FuzzFactory(object):
class FuzzFactory(tempest_lib.base.BaseTestCase):

    default_fuzz_type = 'junk'

    types = [
        'ascii', 'content_types', 'date', 'huge', 'json_recursion', 'junk',
        'number', 'rce', 'sqli', 'traversal', 'url', 'xml', 'xss'
    ]

    def __init__(self):
        self.fuzzers = {}
        self.fuzzers['ascii'] = ASCIIFuzzer()
        self.fuzzers['content_types'] = ContentTypeFuzzer()
        self.fuzzers['date'] = DateFuzzer()
        self.fuzzers['huge'] = HugeFuzzer()
        self.fuzzers['json_recursion'] = JSONRecursionFuzzer()
        self.fuzzers['junk'] = JunkFuzzer()
        self.fuzzers['number'] = NumberFuzzer()
        self.fuzzers['rce'] = RCEFuzzer()
        self.fuzzers['sqli'] = SQLiFuzzer()
        self.fuzzers['traversal'] = PathTraversalFuzzer()
        self.fuzzers['url'] = URLFuzzer()
        self.fuzzers['xml'] = XMLFuzzer()
        self.fuzzers['xss'] = XSSFuzzer()
        super(FuzzFactory, self)

    def get_datasets(self, fuzz_string_types):
        """Get multiple datasets for use in parameterized tests

        :param fuzz_string_types: list of types defined in self.types
        :return dataset as dict for use in parameterized test cases
            :param fuzz_type: the type of fuzz string contained
            :param payload: the fuzz string
        """
        result = {}
        for fuzz_type in fuzz_string_types:
            fuzzer = self.fuzzers[fuzz_type]
            strings = fuzzer.get_strings()
            for string in strings:
                name = '{0}_{1}'.format(
                    fuzz_type, fuzzer.get_fuzz_string_name(string)
                )
                result[name] = {'fuzz_type': fuzz_type, 'payload': string}
        return result

    def get_param_datasets(self, parameters, fuzz_string_types):
        """
        Get multiple datasets for use in parameterized tests for each
        atttribute to be fuzzed

        :param parameters: list of parameters (e.g. filters) to test
        :param fuzz_string_types: one of the types defined in self.types
        :return dataset dict for use in parameterized test case
        """
        result = {}
        for param in parameters:
            for fuzz_type in fuzz_string_types:
                fuzzer = self.fuzzers[fuzz_type]
                strings = fuzzer.get_strings()
                for string in strings:
                    name = '{0}_{1}_{2}'.format(
                        param, fuzz_type,
                        fuzzer.get_fuzz_string_name(string)
                    )
                    result[name] = {'parameter': param,
                                    'fuzz_type': fuzz_type, 'payload': string}
        return result

    def verify_response(self, resp, fuzz_string_type='junk'):
        """
        Verify a response does not contain indications of vulnerability.

        :param resp: A "resp" object with "status_code" and "text"
        :param fuzz_string_type: one of the types defined in self.types
        :return False if the response contains an indication of vulnerability,
            True if not.
        """
        fuzzer = self.fuzzers[fuzz_string_type]
        return fuzzer.verify_response(resp)
        # TODO(ccneill)
        # DO MORE MIDDLEWARE STUFF HERE TO ALLOW BARB + TEMP_LIB TO USE

    def verify_exception(self, method, exc, fuzz_type, *args, **kwargs):
        """
        Verify that the proper exception is thrown from a negative test

        :return tuple (response verified (bool), exception if any)
        """
        fuzzer = self.fuzzers[fuzz_type]
        try:
            resp, model = method(*args, **kwargs)
            return (fuzzer.verify_response(self.get_standard_resp_obj(
                resp.status, str(model.to_dict()))), None)
        except Exception as e:
            self.assertIsInstance(e, (exc))
            status = fuzzer.verify_response(self.get_standard_resp_obj(
                e.resp_body['code'], str(e.resp_body)))
            self.assertTrue(status)
            return (status, e)

    def get_standard_resp_obj(self, status_code, text):
        return {
            'status_code': int(status_code),
            'text': text
        }


class GenericFuzzer(object):

    data = {}

    def get_strings(self):
        """Get a set of fuzz strings

        :return list of raw fuzz strings
        """
        return self.data.values()

    def get_dataset(self, fuzz_string_type):
        """Get an individual fuzz string dataset for use in parameterized tests

        :param fuzz_string_type: one of the types defined in self.types
        :return dataset as dict for use in parameterized test cases
        """
        result = {}
        for string in self.get_strings():
            name = self.get_fuzz_string_name(string)
            result[name] = [string]
        return result

    def get_fuzz_string_name(self, string):
        """Get the name of a fuzz string (pre-defined above or generated)

        :param fuzz_string_type: one of the types defined in self.types
        :param fuzz_string: a fuzz string, either generated on-the-fly or
            predefined
        :return fuzz string name as string
        """
        for name, fuzz_string in self.data.iteritems():
            if string == fuzz_string:
                return name
        return None

    def verify_response(self, resp):
        if resp['status_code'] >= 500:
            # raise Exception("HTTP ERROR: {0}".format(resp['status_code']))
            return False
        return True


class GeneratedDataFuzzer(GenericFuzzer):

    def get_strings(self, fuzz_string_type=None):
        """Get a set of fuzz strings

        :return list of raw fuzz strings
        """
        return []

    def get_fuzz_string_name(self, fuzz_string):
        # Get first 20 characters, trim trailing spaces, convert
        # non-alphanumeric characters to underscores
        fuzz_string = re.sub(
            "[^a-z0-9A-Z]*", "_", fuzz_string[:20].strip()
        )
        return fuzz_string


class ASCIIFuzzer(GeneratedDataFuzzer):

    _type = 'ascii'

    def get_strings(self):
        return [chr(i) for i in range(0, 255)]

    def get_fuzz_string_name(self, string):
        return hex(ord(string))


class JSONRecursionFuzzer(GeneratedDataFuzzer):

    _type = 'json_recursion'

    def get_strings(self):
        obj = {'hax': {}}
        ref = obj
        for i in range(0, 500):
            ref['hax'] = {'hax': {}}
            ref = ref['hax']
        return [json.dumps(obj)]

    def get_fuzz_string_name(self, string):
        return "{0}_length".format(len(string))


class ContentTypeFuzzer(GenericFuzzer):
    data = {
        'atom_xml': 'application/atom+xml',
        'app_xml': 'application/xml',
        'txt_xml': 'text/xml',
        'app_soap_xml': 'application/soap+xml',
        'app_rdf_xml': 'application/rdf+xml',
        'app_rss_xml': 'application/rss+xml',
        'app_js': 'application/javascript',
        'app_ecma': 'application/ecmascript',
        'app_x_js': 'application/x-javascript',
        'txt_js': 'text/javascript',
        'app_pkcs12': 'application/x-pkcs12',
        'app_form': 'application/x-www-form-urlencoded',
        'multipart_enc': 'multipart/encrypted',
        'multipart_form': 'multipart/form-data',
        'msg_http': 'message/http',
        'msg_partial': 'message/partial',
        'junk': 'junk',
    }


class DateFuzzer(GenericFuzzer):
    data = {
        'date_w_null': '2018-02-28T19:14:44.180394\x00',
        'date_w_unicode': '2018-02-28T19:14:44.180394\xff',
        'date_w_format': '2018-02-28T19:%f14:44.180394',
        'huge': '2018-02-28T12:12:12.' + ('4' * 100000),
    }


class HugeFuzzer(GenericFuzzer):
    data = {
        '10^3': 'a' * 10 ** 3,
        '10^4': 'a' * 10 ** 4,
        '10^5': 'a' * 10 ** 5,
        '10^6': 'a' * 10 ** 6,
        '10^7': 'a' * 10 ** 7
    }


class XSSFuzzer(GenericFuzzer):
    data = {
        'double_bracket': '<<script>alert(1);//<</script>',
        'tag_close': '\'"><script>alert(1);</script>',
        'img_js_link': '<IMG SRC=javascript:alert(1)>',
        'img_js_link_w_0x0D': '<IMG SRC=jav&#x0D;ascript:alert(1);>',
        'img_js_link_overencode':
            "<IMG%20SRC='%26%23x6a;avasc%26%23000010ript:alert(1);'>",
        'iframe_js_link': '<IFRAME SRC=javascript:alert(1)></IFRAME>',
        'js_context': '\\\'";alert(1);//'
    }

    def verify_response(self, resp):
        if 'alert(1)' in resp['text']:
            return False
            raise Exception(resp)
            # raise Exception("Possible XSS Vulnerability")
        raise Exception(resp)
        return True


class SQLiFuzzer(GenericFuzzer):
    data = {
        'hex_select': '\\x27\\x4F\\x52 SELECT *',
        'hex_select_2': '\\x27\\x6F\\x72 SELECT *',
        'hex_select_raw': '\x27\x4F\x52 SELECT *',
        'hex_select_raw': '\x27\x6F\x72 SELECT *',
        'hex_union': '\\x27UNION SELECT',
        'hex_union_raw': '\x27UNION SELECT',
        'or_select': '\'"or select *',
        'or_x_is_x': '\' or \'x\'=\'x',
        '0_or_1_is_1': '0 or 1=1',
        '0_or_1_is_1_dashed': '0 or 1=1--',
        'a_or_x_is_x_dquote': 'a" or "x"="x',
        'a_or_x_is_x_squote': 'a\' or \'x\'=\'x',
        'a_or_x_is_x_paren_dqoute': 'a") or ("x"="x',
        'a_or_x_is_x_paren_sqoute': 'a\') or (\'x\'=\'x',
        'a_or_x_is_x_full_statement': '\'a\' or \'x\'=\'x\';',
        'xml':
            '<?xml version="1.0" encoding="ISO-8859-1"?><foo>'
            '<![CDATA[\'or 1=1 or \'\'=\']]></foo>'
    }

    def verify_response(self, resp):
        if 'sql' in resp['text'] or 'syntax' in resp['text']:
            raise Exception("Possible SQLi vulnerability")
        return True


class XMLFuzzer(GenericFuzzer):
    data = {
        'xml_xxe_etc_passwd':
            '<?xml version="1.0" encoding="ISO-8859-1"?>'
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM'
            ' "file:////etc/passwd">]><foo>&xxe;</foo>'
    }

    def verify_response(self, resp):
        if 'root:' in resp['text']:
            raise Exception("Possible XXE vulnerability")
        return True


class JunkFuzzer(GenericFuzzer):
    data = {
        'nullbyte': '\x00',
        'null_escaped': '\\00',
        'higher_ascii': '\x80\xff',
        'url_encoded_junk': '%uf%80%ff%xx%uffff',
        'higher_unicode': '\u1111\uffff',
        'unicode_single_quote': '\u2018',
        'unicode_double_quote': '\u201c',
        'random_symbols': '*!@#$^&()[]{}|.,"\'/'
    }


class NumberFuzzer(GenericFuzzer):
    data = {
        'negative_zero': '-0',
        'negative_hex': '-0xff',
        'overflow': 999999999999999,
        'negative_overflow': -999999999999999,
        'negative_float_overflow': -0.999999999999999,
        'hex_overflow': '0xffffffff',
        'extreme_overflow': 9 ** 100,
        'nullbyte': '\x00'
    }


class RCEFuzzer(GenericFuzzer):
    data = {
        'semicolon_id': ';id',
        'or_id': '||id',
        'pipe_id': '|id',
        'and_id': '&&id',
        'nullbyte_id': '\x00id',
        'urlencoded_nullbyte_id': '%00id',
        'urlencoded_newline_id': '%0aid',
        'backticks_id': '`id`',
        'close_parens_id': ');id'
    }

    def verify_response(self, resp):
        if 'uid=' in resp['text']:
            raise Exception("Possible RCE vulnerability")
        return True


class URLFuzzer(GenericFuzzer):
    data = {
        'javascript': 'javascript:alert(1);',
        'data_img_b64': 'data:image/png;base64,junkjunk',
        'data_xml_b64': 'data:applicaton/xml;charset=utf-8,'
                        + '%3C%3Fxml+version%3D%221.0%22+%3F%3E',
        'file_etc_passwd': 'file:///etc/passwd',
        'relative_etc_passwd': '///etc/passwd',
        'back_slashes': '\etc\passwd',
    }


class PathTraversalFuzzer(GenericFuzzer):
    data = {
        'etc_passwd_generic':
            '../../../../../../../../../../../../etc/passwd',
        'etc_passwd_long_w_null_html':
            '../../../../../../../../../../../../etc/passwd%00.html',
        'etc_passwd_urlencoded':
            '..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd',
        'etc_passwd_w_null_html': '/etc/passwd%00.html',
        'etc_passwd_overencoded_w_null_html':
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd%00'
            'index.html',
        'etc_passwd_cwd_long': '/./././././././././././etc/passwd',
        'etc_passwd_alternating':
            '/..\../..\../..\../..\../..\../..\../etc/passwd',
        'etc_passwd_back_slashes_w_null':
            '\..\..\..\..\..\..\..\..\..\..\etc\passwd%00',
        'etc_passwd_w_nulls': '%00/etc/passwd%00',
        'etc_passwd_urlencoded_w_null':
            '/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../'
            '..%c0%af../etc/passwd%00',
        'etc_passwd_overencoded_w_null':
            '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/'
            '%2e%2e/%2e%2e/etc/passwd%00',
        'etc_passwd_overencoded_w':
            '%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0'
            '%2e%c0%2e%c0%5cetc/passwd',
        'etc_passwd_overencoded_backslashes':
            '%25c0%25ae%25c0%25ae\%25c0%25ae%25c0%25ae\%25c0%25ae%25c0'
            '%25ae\%25c0%25ae%25c0%25ae\%25c0%25ae%25c0%25ae\etc/passwd',
        'etc_passwd_overencoded_unicode':
            '%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216'
            '%uff0e%uff0e%u2216etc/passwd',
        'etc_passwd_urlencoded_w_null_long':
            '%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..'
            '%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..'
            'etc%25%5cpasswd%00',
        'etc_passwd_double_encoded':
            '%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/'
            '%%32%65%%32%65/etc/passwd',
        'etc_passwd_mix_back_slashes':
            '.\\..\\.\\..\\.\\..\\.\\..\\.\\..\\.\\..\\.\\..\\.\\..\\'
            'etc/passwd',
        'etc_passwd_triple_slash':
            '..///..///..///..///..///..///..///..///etc/passwd',
        'etc_passwd_long_leading_dots':
            '.' * 72 + '/../../../../../../etc/passwd'
    }

    def verify_response(self, resp):
        if 'root:' in resp['text']:
            raise Exception("Possible path traversal vulnerability")
        return True
