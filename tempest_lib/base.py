# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import sys

import fixtures
import testresources
import testtools

from tempest_lib.openstack.common import log as logging

LOG = logging.getLogger(__name__)


if sys.version_info >= (2, 7):
    class BaseDeps(testtools.TestCase,
                   testtools.testcase.WithAttributes,
                   testresources.ResourcedTestCase):
        pass
else:
    # Define asserts for py26
    import unittest2

    class BaseDeps(testtools.TestCase,
                   testtools.testcase.WithAttributes,
                   testresources.ResourcedTestCase,
                   unittest2.TestCase):
        pass

at_exit_set = set()


def validate_tearDownClass():
    if at_exit_set:
        LOG.error("tearDownClass does not call the super's "
                  "tearDownClass in these classes: \n"
                  + str(at_exit_set))


class BaseTestCase(BaseDeps):
    setUpClassCalled = False

    @classmethod
    def setUpClass(cls):
        if hasattr(super(BaseTestCase, cls), 'setUpClass'):
            super(BaseTestCase, cls).setUpClass()
        cls.setUpClassCalled = True

    @classmethod
    def tearDownClass(cls):
        at_exit_set.discard(cls)
        if hasattr(super(BaseTestCase, cls), 'tearDownClass'):
            super(BaseTestCase, cls).tearDownClass()

    def setUp(self):
        super(BaseTestCase, self).setUp()
        if not self.setUpClassCalled:
            raise RuntimeError("setUpClass does not calls the super's"
                               "setUpClass in the "
                               + self.__class__.__name__)
        at_exit_set.add(self.__class__)
        test_timeout = os.environ.get('OS_TEST_TIMEOUT', 0)
        try:
            test_timeout = int(test_timeout)
        except ValueError:
            test_timeout = 0
        if test_timeout > 0:
            self.useFixture(fixtures.Timeout(test_timeout, gentle=True))

        if (os.environ.get('OS_STDOUT_CAPTURE') == 'True' or
                os.environ.get('OS_STDOUT_CAPTURE') == '1'):
            stdout = self.useFixture(fixtures.StringStream('stdout')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stdout', stdout))
        if (os.environ.get('OS_STDERR_CAPTURE') == 'True' or
                os.environ.get('OS_STDERR_CAPTURE') == '1'):
            stderr = self.useFixture(fixtures.StringStream('stderr')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stderr', stderr))
        if (os.environ.get('OS_LOG_CAPTURE') != 'False' and
            os.environ.get('OS_LOG_CAPTURE') != '0'):
            self.useFixture(fixtures.LoggerFixture(nuke_handlers=False,
                                                   format=self.log_format,
                                                   level=None))
