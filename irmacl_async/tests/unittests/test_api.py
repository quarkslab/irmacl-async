#
# Copyright (c) 2013-2018 Quarkslab.
# This file is part of IRMA project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the top-level directory
# of this distribution and at:
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# No part of the project, including this file, may be copied,
# modified, propagated, or distributed except according to the
# terms contained in the LICENSE file.

import asynctest
from asynctest import Mock, MagicMock, CoroutineMock, patch
import copy
from pathlib import Path

import irmacl_async.apiclient as module


class TestFunctions(asynctest.TestCase):
    def setUp(self):
        self.api = Mock(spec=module.AAPI, _auth_free=Mock())
        self.api._auth_free.is_set.return_value = True
        self.api._auth_free.wait = CoroutineMock()
        self.api.auth_enabled.return_value = True

    async def test_auth_guarded0(self):
        """ Assert the guarded coroutine is awaited when awaiting for the
            guarder
        """
        f = CoroutineMock()
        gf = module.auth_guarded(f)

        await gf(self.api, "args", kw="kwargs")

        self.api._auth_free.wait.assert_awaited_once_with()
        f.assert_awaited_once_with(self.api, "args", kw="kwargs")

    async def test_auth_guarded1(self):
        """ Assert a non-401 http error is forwarded
        """
        e = module.aiohttp.ClientResponseError(
                "request_info", "history", status=400)
        f = CoroutineMock(side_effect=e)
        gf = module.auth_guarded(f)

        with self.assertRaises(type(e)):
            await gf(self.api, "args", kw="kwargs")

        self.api._auth_free.wait.assert_awaited_once_with()
        f.assert_awaited_once_with(self.api, "args", kw="kwargs")

    async def test_auth_guarded2(self):
        """ Assert an http error is forwarded if authentication is not enabled
        """
        e = module.aiohttp.ClientResponseError(
                "request_info", "history", status=401)
        self.api.auth_enabled.return_value = False
        f = CoroutineMock(side_effect=e)
        gf = module.auth_guarded(f)

        with self.assertRaises(type(e)):
            await gf(self.api, "args", kw="kwargs")

        self.api._auth_free.wait.assert_awaited_once_with()
        f.assert_awaited_once_with(self.api, "args", kw="kwargs")

    async def test_auth_guarded3(self):
        """ Assert the guarded coroutine is awaited when awaiting for the
            guarder
        """
        e = module.aiohttp.ClientResponseError(
                "request_info", "history", status=401)
        f = CoroutineMock(side_effect=(e, None))
        gf = module.auth_guarded(f)

        await gf(self.api, "args", kw="kwargs")

        self.api.login.assert_awaited_once_with()
        self.assertEqual(self.api._auth_free.wait.await_count, 2)
        self.assertEqual(f.await_count, 2)
        f.assert_awaited_with(self.api, "args", kw="kwargs")

    async def test_auth_guarded4(self):
        """ Assert no authentication is made if another one is pending
        """
        e = module.aiohttp.ClientResponseError(
                "request_info", "history", status=401)
        f = CoroutineMock(side_effect=(e, None))
        gf = module.auth_guarded(f)
        self.api._auth_free.is_set.return_value = False

        await gf(self.api, "args", kw="kwargs")

        self.api.login.assert_not_called()
        self.assertEqual(self.api._auth_free.wait.await_count, 2)
        self.assertEqual(f.await_count, 2)
        f.assert_awaited_with(self.api, "args", kw="kwargs")

    @patch("builtins.open")
    async def test_auth_guarded5(self, m_open):
        """ Assert files descritors are reopen if they have been consumed
        """
        e = module.aiohttp.ClientResponseError(
                "request_info", "history", status=401)
        f = CoroutineMock(side_effect=(e, None))
        gf = module.auth_guarded(f)
        self.api._auth_free.is_set.return_value = False
        fd = Mock(spec=module.aiohttp.BufferedReaderPayload, _value=Mock())
        fd._value.name = "fd_name"

        data = Mock(
                spec=module.aiohttp.MultipartWriter,
                _parts=[(fd, 0, 1), (Mock(), 2, 3)])
        data_orig = copy.deepcopy(data)

        await gf(self.api, "args", data=data, kw="kwargs")

        m_open.assert_called_once_with("fd_name", 'rb')
        self.api.login.assert_not_called()
        self.assertEqual(self.api._auth_free.wait.await_count, 2)
        self.assertEqual(f.await_count, 2)
        f.assert_awaited_with(self.api, "args", data=data, kw="kwargs")
        self.assertNotEqual(data._parts, data_orig._parts)


class TestConfig(asynctest.TestCase):

    def test_autoload(self):
        pass

    @patch("irmacl_async.apiclient.ssl")
    def test_ssl0(self, m_ssl):
        config = module.Config(verify=False, ca="/foo/bar.pem")
        import ssl  # Reimport the real ssl for spec
        m_ssl.SSLContext.return_value = m_ctx = Mock(spec=ssl.SSLContext)

        ctx = config.ssl

        self.assertIs(ctx, m_ctx)
        self.assertEqual(ctx.verify_mode, m_ssl.CERT_NONE)
        ctx.load_verify_locations.assert_not_called()

    @patch("irmacl_async.apiclient.ssl")
    def test_ssl1(self, m_ssl):
        config = module.Config(cert="/foo.pem", key="/bar.key", ca="/baz.pem")
        m_ctx = m_ssl.SSLContext.return_value

        ctx = config.ssl

        self.assertEqual(ctx.verify_mode, module.ssl.CERT_REQUIRED)
        m_ctx.load_cert_chain.assert_called_once_with("/foo.pem", "/bar.key")
        m_ctx.load_verify_locations.assert_called_once_with("/baz.pem")


class TestAAPI(asynctest.TestCase):
    forbid_get_event_loop = True

    def setUp(self):
        config = module.Config(api_endpoint="core.irma")
        self.api = module.AAPI(config, loop=self.loop)
        self.api.ssl = "ssl"
        self.resp = MagicMock()
        self.api.session = MagicMock()
        self.api.session.get.return_value.__aenter__.return_value = self.resp
        self.api.session.post.return_value.__aenter__.return_value = self.resp

    @patch("irmacl_async.apiclient.logger")
    @patch("aiohttp.ClientSession")
    async def test_context0(self, m_ClientSession, m_logger):
        m_logger.info = Mock()
        m_ClientSession.return_value = MagicMock()
        self.api.apicheck = False
        self.api.check_version = CoroutineMock()

        async with self.api:
            pass

        m_ClientSession.return_value\
            .__aenter__.assert_awaited_once()
        m_ClientSession.return_value\
            .__aenter__.return_value\
            .__aexit__.assert_awaited_once()
        self.api.check_version.assert_not_awaited()

    @patch("irmacl_async.apiclient.logger")
    @patch("aiohttp.ClientSession")
    async def test_context1(self, m_ClientSession, m_logger):
        m_logger.info = Mock()
        m_ClientSession.return_value = MagicMock()
        self.api.check_version = CoroutineMock()

        async with self.api.tags:
            pass

        m_ClientSession.return_value\
            .__aenter__.assert_awaited_once()
        m_ClientSession.return_value\
            .__aenter__.return_value\
            .__aexit__.assert_awaited_once()
        self.assertEqual(m_logger.info.call_count, 1)

    @patch("irmacl_async.apiclient.logger")
    @patch("aiohttp.ClientSession")
    async def test_context2(self, m_ClientSession, m_logger):
        m_logger.warning = Mock()
        m_ClientSession.return_value = MagicMock()
        self.api.check_version = CoroutineMock(side_effect=RuntimeWarning)

        async with self.api:
            pass

        m_ClientSession.return_value\
            .__aenter__.assert_awaited_once()
        m_ClientSession.return_value\
            .__aenter__.return_value\
            .__aexit__.assert_awaited_once()
        self.assertEqual(m_logger.warning.call_count, 1)

    async def test__get0(self):
        """ Tests that given a session, the request is performed through it
        """
        session = MagicMock()
        session.get.return_value.__aenter__.return_value.read = CoroutineMock()

        await self.api._get("/foo", session)

        session.get.assert_called_once_with(
            "core.irma/foo", headers={}, params=None, ssl="ssl")

    async def test__get1(self):
        query = {"bar": "whatever", "baz": "whatsoever"}
        self.resp.read = CoroutineMock(return_value="content")

        res = await self.api._get("/foo", query=query)

        self.api.session.get.assert_called_once_with(
            "core.irma/foo",
            headers={},
            params={"bar": "whatever", "baz": "whatsoever"},
            ssl="ssl")
        self.resp.raise_for_status.assert_called_once_with()
        self.resp.read.assert_awaited_once_with()
        self.assertEqual(res, "content")

    async def test__get2(self):
        self.resp.content.read = CoroutineMock(side_effect=["cont", "ent", ""])
        stream = MagicMock()

        await self.api._get("/foo", stream=stream)

        self.api.session.get.assert_called_once_with(
            "core.irma/foo", headers={}, params=None, ssl="ssl")
        self.resp.raise_for_status.assert_called_once_with()
        self.resp.content.read.assert_awaited()

        self.assertEqual(stream.write.call_count, 2)
        stream.write.assert_any_call("cont")
        stream.write.assert_any_call("ent")

    async def test__post0(self):
        """ Tests that given a session, the request is performed through it
        """
        session = MagicMock()
        session.post.return_value.__aenter__.return_value.read = \
            CoroutineMock()

        await self.api._post("/foo", session)

        session.post.assert_called_once_with("core.irma/foo", headers={},
                                             ssl="ssl")

    async def test__post1(self):
        data = {"bar": "whatever", "baz": "whatsoever"}
        self.resp.read = CoroutineMock(return_value="content")

        res = await self.api._post("/foo", data=data)

        self.api.session.post.assert_called_once_with(
            "core.irma/foo", headers={}, ssl="ssl", data=data)
        self.resp.raise_for_status.assert_called_once_with()
        self.resp.read.assert_awaited_once_with()
        self.assertEqual(res, "content")

    async def test__format0(self):
        data = b'{"foo": "something", "bar": [{"baz": "somethingelse"}]}'
        self.api.raw = True
        schema = MagicMock()

        res = self.api._format(data, raw=None, schema=schema)

        self.assertEqual(res, data)
        schema.loads.assert_not_called()

    async def test__format1(self):
        data = b'{"foo": "something", "bar": [{"baz": "somethingelse"}]}'
        self.api.raw = False
        schema = MagicMock()

        res = self.api._format(data, raw=True, schema=schema)

        self.assertEqual(res, data)
        schema.loads.assert_not_called()

    async def test__format2(self):
        data = b'{"foo": "something", "bar": [{"baz": "somethingelse"}]}'
        self.api.raw = False

        res = self.api._format(data, raw=None, schema=None)

        self.assertEqual(
            res, {"foo": "something", "bar": [{"baz": "somethingelse"}]})

    async def test__format3(self):
        data = b'{"foo": "something", "bar": [{"baz": "somethingelse"}]}'
        self.api.raw = False
        schema = MagicMock()

        res = self.api._format(data, raw=None, schema=schema)

        self.assertIs(res, schema.loads.return_value)
        schema.loads.assert_called_once_with(data.decode())

    async def test__askpage0(self):
        query = {"foo": "bar"}

        res = self.api._askpage(limit=5, offset=3, query=query)

        self.assertEqual(res, {"foo": "bar", "limit": 5, "offset": 3})
        self.assertEqual(query, {"foo": "bar"})

    async def test__askpage1(self):
        self.api.limit = 4

        res = self.api._askpage()

        self.assertEqual(res, {"limit": 4})

    async def test_about(self):
        self.api._get = CoroutineMock(return_value=b'{"version": "1.2.3"}')

        res = await self.api.about("session")

        self.api._get.assert_awaited_once_with("/about", "session")
        self.assertEqual(res, {"version": "1.2.3"})

    async def test_check_version0(self):
        self.api.about = CoroutineMock(return_value={"version": "2.1.0"})

        with self.assertRaises(RuntimeWarning):
            await self.api.check_version()

    async def test_check_version1(self):
        self.api.about = CoroutineMock(return_value={"version": "2.4.3"})

        await self.api.check_version()

    async def test_check_version2(self):
        self.api.about = CoroutineMock(return_value={"version": "3.0.0"})

        with self.assertRaises(RuntimeWarning):
            await self.api.check_version()

    async def test_login(self):
        self.api._bare_post = CoroutineMock(
                return_value=b'{"token": "eyJ0eXAi"}')

        await self.api.login("irma", "irma")

        self.api._bare_post.assert_awaited_once_with(
                "/auth/login", None, data={
                    'username': 'irma',
                    'password': 'irma'})
        self.assertEqual(
                self.api.headers, {"Authorization": "Bearer eyJ0eXAi"})

    def test_auth_enabled0(self):
        self.api.password = None
        self.assertFalse(self.api.auth_enabled())

    def test_auth_enabled1(self):
        self.api.password = "whatever"
        self.assertTrue(self.api.auth_enabled())


class TestTagsAAPI(TestAAPI):

    async def test_list(self):
        self.api._get = CoroutineMock(
            return_value=b'{"items": [{"id": 3, "text": "foo"}]}')

        res = await self.api.tags.list()

        self.api._get.assert_awaited_once_with("/tags", None)
        self.assertEqual(
            res, [module.TagSchema().load({"id": 3, "text": "foo"})])

    async def test_new0(self):
        self.api._post = CoroutineMock(
            return_value=b'{"id": 3, "text": "foo"}')

        res = await self.api.tags.new("foo")

        self.api._post.assert_awaited_once_with(
            "/tags", None, data={"text": "foo"})
        self.assertEqual(
            res, module.TagSchema().load({"id": 3, "text": "foo"}))

    async def test_new1(self):
        e = module.aiohttp.ClientResponseError("request_info", "history")
        e.status = 400
        self.api._post = CoroutineMock(side_effect=e)

        res = await self.api.tags.new("foo", quiet=True)

        self.api._post.assert_awaited_once_with(
            "/tags", None, data={"text": "foo"})
        self.assertIsNone(res)

    async def test_new2(self):
        e = module.aiohttp.ClientResponseError("request_info", "history")
        e.status = 500
        self.api._post = CoroutineMock(side_effect=e)

        with self.assertRaises(module.IrmaError):
            await self.api.tags.new("foo", quiet=True)

        self.api._post.assert_awaited_once_with(
            "/tags", None, data={"text": "foo"})


class TestProbesAAPI(TestAAPI):

    async def test_list(self):
        self.api._get = CoroutineMock(
            return_value=b'{"total":2, "data": ["ClamAV", "windefender"]}')

        res = await self.api.probes.list()

        self.api._get.assert_awaited_once_with("/probes", None)
        self.assertEqual(res, ["ClamAV", "windefender"])


class TestFilesAAPI(TestAAPI):

    @patch("aiohttp.MultipartWriter")
    async def test__prepare_file(self, m_MultipartWriter):
        data = Mock()
        m_MultipartWriter.return_value.__enter__.return_value = data

        res = self.api.files._prepare_file("content", "/foo/bar")
        # no much logic to test

        self.assertIs(res, data)

    async def test_list(self):
        filesapi = self.api.files
        filesapi.search = CoroutineMock()

        await filesapi.list()

        filesapi.search.assert_awaited_once_with({}, None, None, None, None)

    async def test_search0(self):
        self.api._get = CoroutineMock(return_value=b"{}")

        await self.api.files.search(query={"name": ".txt"}, limit=3)

        self.api._get.assert_awaited_once_with(
            "/files", None, {"name": ".txt", "limit": 3})

    @patch("irmacl_async.apiclient.logger")
    async def test_search1(self, m_logger):
        e = module.aiohttp.ClientResponseError("request_info", "history")
        self.api._get = CoroutineMock(side_effect=e)

        with self.assertRaises(module.IrmaError):
            await self.api.files.search(query={"tags": [1, 2, 3]}, limit=4)

        self.assertEqual(m_logger.warning.call_count, 1)
        self.api._get.assert_awaited_once_with(
            "/files", None, {"tags": "1,2,3", "limit": 4})

    async def test_results(self):
        self.api._get = CoroutineMock(
                return_value=b'{"id": "someid", "file_sha256": "12..45"}')

        await self.api.files.results("sha256", offset=2)

        self.api._get.assert_awaited_once_with(
            "/files/sha256", None, {"offset": 2})

    async def test_add_tag0(self):
        e = module.aiohttp.ClientResponseError("request_info", "history")
        self.api._get = CoroutineMock(side_effect=e)

        with self.assertRaises(module.IrmaError):
            await self.api.files.add_tag("sha256", 3)

        self.api._get.assert_awaited_once_with(
            "/files/sha256/tags/3/add", None)

    async def test_add_tag1(self):
        e = module.aiohttp.ClientResponseError("request_info", "history")
        e.status = 400
        self.api._get = CoroutineMock(side_effect=e)

        await self.api.files.add_tag("sha256", 3, quiet=True)

        self.api._get.assert_awaited_once_with(
            "/files/sha256/tags/3/add", None)

    async def test_remove_tag0(self):
        e = module.aiohttp.ClientResponseError("request_info", "history")
        self.api._get = CoroutineMock(side_effect=e)

        with self.assertRaises(module.IrmaError):
            await self.api.files.remove_tag("sha256", 3)

        self.api._get.assert_awaited_once_with(
            "/files/sha256/tags/3/remove", None)

    async def test_remove_tag1(self):
        e = module.aiohttp.ClientResponseError("request_info", "history")
        e.status = 400
        self.api._get = CoroutineMock(side_effect=e)

        await self.api.files.remove_tag("sha256", 3, quiet=True)

        self.api._get.assert_awaited_once_with(
            "/files/sha256/tags/3/remove", None)

    async def test_upload(self):
        filesapi = self.api.files
        filesapi.new = CoroutineMock()
        path = MagicMock()
        path.as_posix.return_value = "/foo/bar"
        path.open.return_value.__enter__.return_value = "fd"

        await filesapi.upload(path)

        filesapi.new.assert_awaited_once_with("fd", "/foo/bar", None, None)

    async def test_new(self):
        filesapi = self.api.files
        self.api._post = CoroutineMock(
                return_value=b'{"id": "someid", "file_sha256": "12..45"}')
        filesapi._prepare_file = Mock(return_value="data")

        await filesapi.new("content", "/foo/bar")

        self.api._post.assert_awaited_once_with(
            "/files_ext", None, data="data")

    async def test_download(self):
        path = MagicMock()
        path.open.return_value.__enter__.return_value = "fd"
        self.api._get = CoroutineMock()

        await self.api.files.download("sha256", path)

        self.api._get.assert_awaited_once_with(
            "/files/sha256/download", None, stream="fd")


class TestScanAAPI(TestAAPI):

    async def test_list(self):
        self.api._get = CoroutineMock(return_value=b'{"id": "someid"}')

        await self.api.scans.list(limit=3)

        self.api._get.assert_awaited_once_with("/scans", None, {"limit": 3})

    async def test_get(self):
        self.api._get = CoroutineMock(return_value=b'{"id": "someid"}')

        await self.api.scans.get("scan-uuid")

        self.api._get.assert_awaited_once_with(
            "/scans/scan-uuid", None)

    async def test_waitfor(self):
        scansapi = self.api.scans
        scanschema = module.ScanSchema()
        scansapi.get = CoroutineMock(side_effect=(
            scanschema.load(
                {"id": "127d134f-0e1e-4238-87b4-29ee87ebe60a", "status": 30}
                ),
            scanschema.load(
                {"id": "127d134f-0e1e-4238-87b4-29ee87ebe60a", "status": 40}
                ),
            scanschema.load(
                {"id": "127d134f-0e1e-4238-87b4-29ee87ebe60a", "status": 50}
                ),
            scanschema.load(
                {"id": "127d134f-0e1e-4238-87b4-29ee87ebe60a", "status": 50}
                ),
        ))

        await scansapi.waitfor("127d134f-0e1e-4238-87b4-29ee87ebe60a")

        self.assertEqual(scansapi.get.call_count, 4)

    async def test_result(self):
        self.api._get = CoroutineMock(
                return_value=b'{"id": "someid", "file_sha256": "12..45"}')

        await self.api.scans.result("fileext-uuid", full=True)

        self.api._get.assert_awaited_once_with(
            "/files_ext/fileext-uuid", None, {"formatted": "no"})

    async def test_new(self):
        self.api._post = CoroutineMock(return_value=b'{"id": "someid"}')

        await self.api.scans.new()

        self.api._post.assert_awaited_once_with("/scans", None)

    async def test_launch0(self):
        self.api._post = CoroutineMock(return_value=b'{"id": "someid"}')

        await self.api.scans.launch(
                ["fe-uuid1", "fe-uuid2"], probes=["foo", "bar"], force=True,
                mimetype_filtering=True, resubmit_files=False)

        self.api._post.assert_awaited_once_with(
            "/scans", None, json={
                "files": ["fe-uuid1", "fe-uuid2"],
                "options": {
                    "probes": ["foo", "bar"],
                    "force": True,
                    "mimetype_filtering": True,
                    "resubmit_files": False,
                }})

    async def test_launch1(self):
        scansapi = self.api.scans
        scansapi.waitfor = CoroutineMock()
        self.api._post = CoroutineMock(
                return_value=b'{"id": "8e897dbc-b93b-49a7-8b3e-7404bb3ac800"}')

        await scansapi.launch(
                ["fe-uuid1", "fe-uuid2"], linger=True, probes=["foo", "bar"],
                force=True, mimetype_filtering=True, resubmit_files=False)

        self.api._post.assert_awaited_once_with(
            "/scans", None, json={
                "files": ["fe-uuid1", "fe-uuid2"],
                "options": {
                    "probes": ["foo", "bar"],
                    "force": True,
                    "mimetype_filtering": True,
                    "resubmit_files": False,
                }})

        scansapi.waitfor.assert_awaited_once_with(
            module.ScanSchema(only=('id',))
                .loads(self.api._post.return_value.decode()),
            None, None)

    async def test_scan0(self):
        scansapi = self.api.scans
        scansapi.api = Mock()
        scansapi.api.files._prepare_file = Mock(return_value="data")
        scansapi._post = CoroutineMock(return_value='{"id": "someid"}')
        path = MagicMock(spec=Path)

        await scansapi.scan(path, probes=["baz"], force=True)

        scansapi._post.assert_awaited_once_with(
            "/scans/quick", None, data="data")

    async def test_scan1(self):
        scansapi = self.api.scans
        scansapi.api = Mock()
        scansapi.api.files._prepare_file = Mock(return_value="data")
        scansapi._post = CoroutineMock(
            return_value=b'{"id": "33c78169-c204-446b-a633-059fffeef5a0"}')
        scansapi.waitfor = CoroutineMock()
        scansapi._format = self.api._format
        path = MagicMock(spec=Path)

        await scansapi.scan(path, linger=True, probes=["baz"], force=True)

        scansapi._post.assert_awaited_once_with(
            "/scans/quick", None, data="data")
        scansapi.waitfor.assert_awaited_once_with(
            module.ScanSchema(only=('id',))
                .loads(scansapi._post.return_value.decode()),
            None, None)

    async def test_scan2(self):
        scansapi = self.api.scans
        scansapi.launch = CoroutineMock()
        scansapi.api = Mock()
        # In fact upload returns a FileExt
        scansapi.api.files.upload = CoroutineMock(side_effect=(
            "fe1-uuid", "fe2-uuid",))

        await scansapi.scan(["foo", "bar"], probes=["baz"], force=True)

        self.assertEqual(scansapi.api.files.upload.await_count, 2)
        scansapi.launch.assert_awaited_once_with(
            ["fe1-uuid", "fe2-uuid"], None, None, False, probes=["baz"],
            force=True, mimetype_filtering=None, resubmit_files=None)

    async def test_cancel(self):
        self.api._post = CoroutineMock(return_value=b'{"id": "someid"}')

        await self.api.scans.cancel("scan-uuid")

        self.api._post.assert_awaited_once_with(
            "/scans/scan-uuid/cancel", None)


class TestScanRetrievalCodeAAPI(TestAAPI):

    async def test_new(self):
        self.api._post = CoroutineMock(return_value=b'{"id": "someid"}')

        await self.api.srcodes.new("scanid")

        self.api._post.assert_awaited_once_with("/scan_retrieval_codes", None,
                                                data={"scan_id": "scanid"})

    async def test_get(self):
        self.api._get = CoroutineMock(return_value=b'{"id": "somescanid"}')

        await self.api.srcodes.get("srcode-id")

        self.api._get.assert_awaited_once_with(
            "/scan_retrieval_codes/srcode-id", None)

    async def test_get_file(self):
        self.api._get = CoroutineMock(
            return_value=b'{"id": "somefileid", "file_sha256": "12..45"}')

        await self.api.srcodes.get_file(srcode="srcode-id", file="file-id")

        self.api._get.assert_awaited_once_with(
            "/scan_retrieval_codes/srcode-id/files_ext/file-id", None)

    async def test_download_file1(self):
        path = MagicMock()
        path.open.return_value.__enter__.return_value = "fd"
        self.api._get = CoroutineMock()

        await self.api.srcodes.download_file(srcode="srcode-id",
                                             file="file-id",
                                             dstpath=path)

        self.api._get.assert_awaited_once_with(
            "/scan_retrieval_codes/srcode-id/files_ext/file-id/download",
            None, stream="fd")

    async def test_download_file2(self):
        path = MagicMock()
        path.open.return_value.__enter__.return_value = "fd"

        e = module.aiohttp.ClientResponseError("request_info", "history")
        e.status = 403
        self.api._get = CoroutineMock(side_effect=e)

        with self.assertRaises(module.IrmaError):
            await self.api.srcodes.download_file(srcode="srcode-id",
                                                 file="file-id",
                                                 dstpath=path)


if __name__ == "__main__":
    asynctest.main()
