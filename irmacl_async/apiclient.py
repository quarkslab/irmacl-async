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

import aiohttp
import asyncio
import copy
import functools
import json
import logging
import os
from pathlib import Path
from pkg_resources import parse_version
import ssl
import types
import yaml

from irma.shared.schemas import (
    apiid,
    ValidationError,
)
from irma.shared.schemas.v2 import (
    FileExtSchema,
    FileResultSchema,
    Paginated,
    ScanRetrievalCodeSchema,
    ScanSchema,
    SRScanSchema,
    TagSchema,
)


__all__ = ['AAPI', 'Config', 'IrmaError']

# TODO: real log configuration
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("irmacl")


def auth_guarded(call):
    @functools.wraps(call)
    async def wrapper(api, *args, **kwargs):
        try:
            await api._auth_free.wait()
            return await call(api, *args, **kwargs)
        except aiohttp.ClientResponseError as e:
            if e.status != 401 or not api.auth_enabled():
                raise

            logger.info("Request denied, authentication required: %s", e)
            if api._auth_free.is_set():
                # Try to login only if there is not another pending task to do
                # it
                api._auth_free.clear()
                await api.login()
                api._auth_free.set()

            # Reopen file descriptors that were consumed by the previous
            # request
            data = kwargs.get('data')
            if data and isinstance(data, aiohttp.MultipartWriter):
                fds = (fd for fd, *_ in data._parts
                       if isinstance(fd, aiohttp.BufferedReaderPayload))
                for fd in fds:
                    # Reopen file descriptors
                    fd._value = open(fd._value.name, 'rb')

            # This call is unguarded. It will not try to login in case of
            # failure
            await api._auth_free.wait()
            return await call(api, *args, **kwargs)
            # NOTE: file descriptors are automatically closed by
            # aiohttp.MultipartWriter when consumed
    return wrapper


class IrmaError(Exception):
    pass


class Config:

    CONF_LOCATIONS = [
        Path.cwd(),
        Path(os.environ.get("IRMA_CONF", "")),
        Path.home(),
        Path("/etc/irma"),
    ]
    CONF_FILE = "irma.yml"

    @classmethod
    def autoload(cls):
        """ Load a configuration from a irma.conf file.

        :returns: the configuration from a well-located irma.conf file, or the
            default configuration if none is found

        """
        for loc in cls.CONF_LOCATIONS:
            try:
                conffile = loc / cls.CONF_FILE
                with conffile.open() as f:
                    return Config(**yaml.safe_load(f))
            except IOError:
                # File does not exist or cannot be read
                pass
        logger.warning(
            "%s config file not found, default configuration is applied",
            cls.CONF_FILE)
        return Config()

    def __init__(
            self, api_endpoint="http://localhost/api/v2",
            verify=True, ca=None, cert=None, key=None,
            submitter="cli", submitter_id="", user="irma", password="irma"):
        """
        :param api_endpoint: url of the IRMA API (default
            "http://localhost/api/v2")
        :param verify: bool, verify server certificate (default True)
        :param ca: path to a CA file (default None)
        :param cert: path to the client certificate to use (default None)
        :param key: path to the client private key to use (default None)
        :param submitter: submitter to advertize to IRMA (default "cli")
        :param submitter_id: submitter specific identifier (default "")
        :param user, password: credentials to authenticate with (default
            "irma", "irma")

        """
        self.api_endpoint = api_endpoint
        self.verify = verify
        self.ca = ca
        self.cert = cert
        self.key = key
        self.submitter = submitter
        self.submitter_id = submitter_id
        self.user = user or submitter
        self.password = password

    @property
    def ssl(self):
        ctx = ssl.SSLContext()
        if self.verify:
            ctx.verify_mode = ssl.CERT_REQUIRED
            if self.cert and self.key:
                ctx.load_cert_chain(self.cert, self.key)
            if self.ca:
                ctx.load_verify_locations(self.ca)
        else:
            ctx.verify_mode = ssl.CERT_NONE
        return ctx


class AAPI:

    IRMA_VERSION_MIN = parse_version("v2.4.0")
    IRMA_VERSION_MAX = parse_version("v3.0.0a0")

    def __init__(
            self, config=None, *, apicheck=True, timeout=15, limit=None,
            raw=False, loop=None):
        """
        :param config: Config object to use (default None ie.
            Config.autoload())
        :param apicheck: check that the IRMA counterpart is in the expected
            version (default True)
        :param timeout: time in seconds a request should be completed in before
            aborting it (default 15s). Not implemented
        :param limit: max number of simultaneous connections (default None).
            Not implemented
        :param raw: default value about response formating (default False)
        :param loop: event loop to use (default None ie.
            asyncio.get_event_loop())

        """
        config = config or Config.autoload()

        self.url = config.api_endpoint
        self.submitter = config.submitter
        self.submitter_id = config.submitter_id
        self.user = config.user
        self.password = config.password
        self.ssl = config.ssl

        self.apicheck = apicheck
        self.limit = limit
        self.raw = raw

        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._loop = loop or asyncio.get_event_loop()

        # Represent the absence of any authentication process. Needed to
        # authenticate only once when several 401 are received.
        self._auth_free = asyncio.Event(loop=self._loop)
        self._auth_free.set()

        self.session = None
        self.headers = {}

    async def __aenter__(self):
        self.session = await aiohttp.ClientSession(
                timeout=self._timeout, loop=self._loop).__aenter__()

        if self.apicheck:
            try:
                await self.check_version()
                logger.info("Check API version: OK")
            except RuntimeWarning as e:
                logger.warning(
                    "Check API version: IRMA version (%s) not included in"
                    " compatibility range [%s, %s[", e,
                    self.IRMA_VERSION_MIN, self.IRMA_VERSION_MAX)
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        self.headers = {}
        return await self.session.__aexit__(exc_type, exc_value, traceback)

    async def _bare_get(self, route, session=None, query=None, stream=None):
        """ Perform a GET request on a given route

        :param route: route to query
        :param session: custom session to use (default None)
        :param query: dict representing the fields to query
        :param stream: file descriptor to write the response into (default
            None). Especially useful when downloading a file.
        :returns: body of the response
        :raises: aiohttp.ClientResponseError

        """
        if session is None:
            session = self.session

        url = self.url + route
        async with session.get(url, params=query, ssl=self.ssl,
                               headers=self.headers) as resp:
            logger.debug("GET %s - %s", resp.url, self.headers)
            resp.raise_for_status()
            if stream:
                while True:
                    chunk = await resp.content.read(4096)
                    if not chunk:
                        break
                    stream.write(chunk)
            else:
                return await resp.read()

    _get = auth_guarded(_bare_get)

    async def _bare_post(self, route, session=None, **req_params):
        """ Perform a POST request on a given route

        :param route: route to query
        :param session: custom session to use (default None)
        :param **req_params: parameters of the request. Usualy only data=.. or
            json=.. would be useful
        :returns: body of the response
        :raises: aiohttp.ClientResponseError

        """
        if session is None:
            session = self.session

        url = self.url + route
        logger.debug("POST %s - %s - %s", url, req_params, self.headers)
        async with session.post(url, ssl=self.ssl, headers=self.headers,
                                **req_params) as resp:

            resp.raise_for_status()
            return await resp.read()

    _post = auth_guarded(_bare_post)

    def _format(self, res, raw=None, schema=None):
        """ Format request result

        :param res: raw result of the request
        :param raw: bool, return unprocessed bytes (default None)
        :param schema: schema to process the response with (default None). If
        no schema is given the result is processed as native json
        :returns: formatted result of the request

        """
        raw = raw if raw is not None else self.raw
        if raw:
            return res
        elif schema is None:
            return json.loads(res.decode())
        else:
            try:
                if isinstance(schema, (types.MethodType, types.FunctionType)):
                    # Dynamically load schema based on input data
                    res = json.loads(res.decode())
                    schema = schema(res)()
                    return schema.load(res)
                else:
                    return schema.loads(res.decode())
            except ValidationError as e:
                logger.error("deserialisation failed: %s", e)
                logger.info("deserialisation failed - data: %s", e.data)

    def _askpage(self, offset=None, limit=None, query=None):
        """ Construct a query for asking a page of a paginated result

        :param offset: offset of the first element (default None)
        :param limit: size of the page (default None)
        :param query: pre-existing query the pagination have to be added to
            (default None). It is not modified by this method, but copied
        :returns: a query for pagination

        """
        query = copy.copy(query) if query is not None else {}

        if limit is not None:
            query['limit'] = limit
        elif self.limit is not None:
            query['limit'] = self.limit

        if offset is not None:
            query['offset'] = offset

        return query

    async def about(self, session=None, raw=None):
        """ Query information about IRMA itself

        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: dict with misc info

        """
        res = await self._get("/about", session)
        return self._format(res, raw)

    async def check_version(self):
        """ Check that the queried IRMA API is compatible with this version of
            irmacl-async

        :raises: RuntimeWarning if incompatible versions

        """
        version = await self.about(raw=False)
        version = parse_version(version["version"])
        if not (self.IRMA_VERSION_MIN <= version < self.IRMA_VERSION_MAX):
            raise RuntimeWarning(version)

    async def login(self, username=None, password=None, session=None):
        """ Authenticate onto IRMA and set the headers accordingly

        :param username, password: credentials to use (default None)
        :param session: custom session to use (default None)
        :raises: aiohttp.ClientResponseError

        """
        data = {
            "username": username or self.user,
            "password": password or self.password,
        }
        logger.info("Authenticate as %s", data["username"])
        res = await self._bare_post("/auth/login", session, data=data)
        res = self._format(res, raw=False)
        self.headers["Authorization"] = "Bearer " + res["token"]

    def auth_enabled(self):
        return bool(self.password)

    @property
    def tags(self):
        """ Sub-API dedicated to tags
        """
        return TagsAAPI(self)

    @property
    def probes(self):
        """ Sub-API dedicated to probes
        """
        return ProbesAAPI(self)

    @property
    def files(self):
        """ Sub-API dedicated to files
        """
        return FilesAAPI(self)

    @property
    def scans(self):
        """ Sub-API dedicated to scans
        """
        return ScansAAPI(self)

    @property
    def srcodes(self):
        """ Sub-API dedicated to srcodes
        """
        return SRCodeAAPI(self)


class AAPIView:

    """ Specialized view on a generalist AAPI.
    """

    def __init__(self, api):
        self.api = api

    def __getattr__(self, name):
        return getattr(self.api, name)

    async def __aenter__(self):
        await self.api.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return await self.api.__aexit__(exc_type, exc_value, traceback)


class TagsAAPI(AAPIView):

    async def list(self, session=None, raw=None):
        """ List the entire collection of available tags

        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the list of tags

        """
        res = await self._get("/tags", session)
        # TODO: cleanup. It is ugly to use a paginated schema to process an
        # unpaginated result
        return self._format(res, raw, schema=Paginated(TagSchema)(
            only=("items",)))["items"]

    async def new(self, text, quiet=False, session=None, raw=None):
        """ Create a new tag

        :param text: name of the tag
        :param quiet: bool, do not raise an exception if the tag already
            exists (default False)
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: a newly created tag

        """
        data = {"text": text}
        try:
            res = await self._post("/tags", session, data=data)
            return self._format(res, raw, schema=TagSchema())
        except aiohttp.ClientResponseError as e:
            logger.warning(e)
            if not (quiet and e.status == 400):
                raise IrmaError("Tag 'text' already exists.")


class ProbesAAPI(AAPIView):

    async def list(self, session=None, raw=None):
        """ List the entire collection of available probes

        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the list of tags

        """
        res = await self._get("/probes", session)
        return self._format(res, raw)["data"]


class FilesAAPI(AAPIView):

    def _prepare_file(self, content, filename):
        with aiohttp.MultipartWriter('form-data') as data:
            filesdata = aiohttp.payload.get_payload(content)
            filesdata.set_content_disposition(
                    'form-data', name='files', filename=filename)

            data.append(filesdata)
            jsondata = {'submitter': self.submitter}
            if self.submitter_id:
                jsondata["submitter_id"] = self.submitter_id
            jsondata = aiohttp.JsonPayload(jsondata)
            jsondata.set_content_disposition('form-data', name='json')
            data.append(jsondata)
        return data

    async def list(self, offset=None, limit=None, session=None, raw=None):
        """ List a page of the collection of files

        :param offset: offset for pagination (default None)
        :param limit: custom limit for pagination (default None)
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the queried page of the list of files

        """
        return await self.search({}, offset, limit, session, raw)

    async def search(
            self, query=None, offset=None, limit=None, session=None, raw=None):
        """ List a page of matching results of a query on files

        :param query: parameters of the query. It must only contains the keys
            'name', 'hash' an 'tags' (default None ie. no filter)
        :param offset: offset for pagination (default None)
        :param limit: custom limit for pagination (default None)
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the queried page of the list of files
        :raises: IrmaError

        """
        if query and isinstance(query.get("tags"), list):
            query["tags"] = ','.join(str(apiid(i)) for i in query["tags"])
        query = self._askpage(offset, limit, query)
        try:
            res = await self._get("/files", session, query)
            schema = Paginated(
                    FileExtSchema,
                    exclude=('probe_results',)
                )(exclude=('data',))
            return self._format(res, raw, schema=schema)
        except aiohttp.ClientResponseError as e:
            logger.warning(e)
            raise IrmaError("Bad resquest")

    async def results(
            self, file, offset=None, limit=None, session=None, raw=None):
        """ List a page of the results associated to file

        :param file: file or sha256
        :param offset: offset for pagination (default None)
        :param limit: custom limit for pagination (default None)
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the queried page of the list of results
        :raises: aiohttp.ClientResponseError

        """
        route = "/files/{}".format(apiid(file))
        query = self._askpage(offset, limit)
        res = await self._get(route, session, query)
        return self._format(res, raw, schema=FileResultSchema())

    async def add_tag(
            self, file, tag, quiet=False, session=None):
        """ Add a tag to a file

        :param file: file or sha256 to add the tag to
        :param tag: tag or id to add
        :param quiet: bool, do not raise an exception if the file is
            already tagged with this tag (default False)
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :raises: aiohttp.ClientResponseError
        :raises: IrmaError when tag is already present

        """
        route = "/files/{}/tags/{}/add".format(apiid(file), apiid(tag))
        try:
            await self._get(route, session)
        except aiohttp.ClientResponseError as e:
            logger.warning(e)
            if not (quiet and e.status == 400):
                raise IrmaError("File {} is already tagged with tag {}."
                                .format(file, tag))

    async def remove_tag(
            self, file, tag, quiet=False, session=None):
        """ Remove a tag from a file

        :param file: file or sha256 to remove the tag from
        :param tag: tag or id to remove
        :param quiet: bool, do not raise an exception if the file is not
            tagged with this tag (default False)
        :param session: custom session to use (default None)
        :raises: aiohttp.ClientResponseError
        :raises: IrmaError when tag cant be removed

        """
        route = "/files/{}/tags/{}/remove".format(apiid(file), apiid(tag))
        try:
            await self._get(route, session)
        except aiohttp.ClientResponseError as e:
            logger.warning(e)
            if not (quiet and e.status == 400):
                raise IrmaError("File {} is already NOT tagged with tag {}."
                                .format(file, tag))

    async def upload(self, srcpath, session=None, raw=None):
        """ Create a new file from a local path

        :param srcpath: path to upload
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: newly created file_ext
        :raises: aiohttp.ClientResponseError

        """
        with srcpath.open('rb') as src:
            return await self.new(src, srcpath.as_posix(), session, raw)

    async def new(self, content, filename, session=None, raw=None):
        """ Create a new file

        :param content: bytes or file descriptor
        :param filename: name of the file for IRMA
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: newly created file_ext
        :raises: aiohttp.ClientResponseError

        """
        data = self._prepare_file(content, filename)
        res = await self._post("/files_ext", session, data=data)
        return self._format(res, raw, schema=FileExtSchema.dynschema)

    async def download(
            self, file, dstpath, session=None):
        """ Download a file from the API

        :param file: file or sha256 to download
        :param dstpath: path to write the downloaded file on
        :param session: custom session to use (default None)
        :raises: aiohttp.ClientResponseError

        """
        route = '/files/{}/download'.format(apiid(file))
        with dstpath.open('wb') as fd:
            await self._get(route, session, stream=fd)


class ScansAAPI(AAPIView):

    async def list(self, offset=None, limit=None, session=None, raw=None):
        """ List a page of the collection of scans

        :param offset: offset for pagination (default None)
        :param limit: custom limit for pagination (default None)
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the queried page of the list of scans
        :raises: aiohttp.ClientResponseError

        """
        query = self._askpage(offset, limit)
        res = await self._get('/scans', session, query)
        schema = Paginated(ScanSchema)(exclude=("items",))
        return self._format(res, raw, schema=schema)

    async def get(self, scan, session=None, raw=None):
        """ Query a scan

        :param scan: uuid or scan to query
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the queried scan
        :raises: aiohttp.ClientResponseError

        """
        route = "/scans/{}".format(apiid(scan))
        res = await self._get(route, session)
        return self._format(res, raw, schema=ScanSchema())

    async def waitfor(self, scan, session=None, raw=None):
        """ Wait for a scan to be finished and return it

        :param scan: uuid or scan to wait for
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the queried scan, once finished

        """
        while True:
            res = await self.get(scan, session, raw=False)
            if res.status < 50:
                await asyncio.sleep(1)
            else:
                break
        # Extra call to simplify 'raw' handling
        return await self.get(scan, session, raw)

    async def result(self, fileext, full=False, session=None, raw=None):
        """ Get detailed results on a specific scanned file

        :param fileext: fileext or uuid to get results of
        :param full: bool, get full results or shortened ones (default False)
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the detailed results

        """
        route = "/files_ext/{}".format(apiid(fileext))
        query = {"formatted": "no"} if full else {}
        res = await self._get(route, session, query)
        return self._format(res, raw, schema=FileExtSchema.dynschema)

    async def new(self, session=None, raw=None):
        """ Create a new empty scan

        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: a newly created scan

        """
        res = await self._post("/scans", session)
        return self._format(res, raw, schema=ScanSchema())

    async def launch(
            self, fileexts, session=None, raw=None, linger=False, *,
            probes=None, force=None, mimetype_filtering=None,
            resubmit_files=None):
        """ Create and launch a scan on already uploaded files

        :param fileexts: list of fileexts or uuids to enclose
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :param linger: bool, wait for the scan to complete (default False)
        :param probes: probes to run on (default None ie. all)
        :param force, mimetype_filtering, resubmit_files: scan options (default
            None)
        :returns: a newly created scan
        :raises: aiohttp.ClientResponseError

        """
        options = {}
        if force is not None:
            options['force'] = force
        if probes is not None:
            options['probes'] = probes
        if resubmit_files is not None:
            options['resubmit_files'] = resubmit_files
        if mimetype_filtering is not None:
            options['mimetype_filtering'] = mimetype_filtering

        data = {
            "files": [apiid(fe) for fe in fileexts],
            "options": options,
        }
        res = await self._post("/scans", session, json=data)
        if linger:
            scan = self._format(res, raw=False, schema=ScanSchema())
            return await self.waitfor(scan, session, raw)
        else:
            return self._format(res, raw, schema=ScanSchema())

    async def scan(
            self, srcpaths, session=None, raw=None, linger=False, *,
            probes=None, force=None, mimetype_filtering=None,
            resubmit_files=None):
        """ Upload multiple files and run a scan on them

        :param srcpaths: a path or a collection of paths to scan
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :param linger: bool, wait for the scan to complete (default False)
        :param probes: probes to run on (default None ie. all)
        :param force, mimetype_filtering, resubmit_files: scan options (default
            None)
        :returns: a newly created scan
        :raises: aiohttp.ClientResponseError

        NOTE: if `srcpaths` is a single Path, then the `/scan/quick` API route
        will be used and so `probes`, `force`, `mimetype_filtering` and
        `resubmit_files` are ignored. Send a collection of one file to prevent
        it.

        """
        if isinstance(srcpaths, Path):
            srcpath = srcpaths  # just to be clear
            with srcpath.open('rb') as src:
                data = self.api.files._prepare_file(src, srcpath.as_posix())
                res = await self._post("/scans/quick", session, data=data)
            if linger:
                scan = self._format(res, raw=False, schema=ScanSchema())
                return await self.waitfor(scan, session, raw)
            else:
                return self._format(res, raw, schema=ScanSchema())
        else:
            files = [self.api.files.upload(p) for p in srcpaths]
            files = await asyncio.gather(*files)
            return await self.launch(
                    files, session, raw, linger, probes=probes, force=force,
                    mimetype_filtering=mimetype_filtering,
                    resubmit_files=resubmit_files)

    async def cancel(self, scan, session=None, raw=None):
        """ Cancel a running scan

        :param scan: uuid or scan to cancel
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the canceled scan
        :raises: aiohttp.ClientResponseError
        :raises: IrmaError if the scan is already finished

        """
        route = "/scans/{}/cancel".format(apiid(scan))
        try:
            res = await self._post(route, session)
            return self._format(res, raw, schema=ScanSchema())
        except aiohttp.ClientResponseError as e:
            if e.status == 400:
                raise IrmaError(
                    "Scan {} finished, cannot cancel it".format(apiid(scan)))
            raise


class SRCodeAAPI(AAPIView):

    async def new(self, scan, session=None, raw=None):
        """ Create a new scan retrieval code

        :param scan: scan or scan id
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: a newly created srcode

        """
        data = {"scan_id": apiid(scan)}
        res = await self._post("/scan_retrieval_codes", session, data=data)
        return self._format(res, raw, schema=ScanRetrievalCodeSchema())

    async def get(self, srcode, session=None, raw=None):
        """ Get a scan by srcode

        :param srcode: scan retrieval code value
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the scan associated with the srcode

        """
        route = "/scan_retrieval_codes/{}".format(apiid(srcode))
        res = await self._get(route, session)
        return self._format(res, raw, schema=SRScanSchema())

    async def get_file(self, srcode, file, session=None, raw=None):
        """ Get file details in a scan identified by srcode

        :param srcode: scan retrieval code value
        :param file: file or file id
        :param session: custom session to use (default None)
        :param raw: bool, return unprocessed bytes (default None)
        :returns: the file associated with the srcode and file

        """
        route = "/scan_retrieval_codes/{}/files_ext/{}".format(
                apiid(srcode),
                apiid(file))
        res = await self._get(route, session)
        return self._format(res, raw, schema=FileExtSchema.dynschema)

    async def download_file(
            self, srcode, file, dstpath, session=None):
        """ Download a file from the API

        :param srcode: scan retrieval code value
        :param file: file id to download
        :param dstpath: path to write the downloaded file on
        :param session: custom session to use (default None)
        :raises: aiohttp.ClientResponseError
        :raises: IrmaError on wrong srcode, scan not finished or file
        potentially harmful

        """
        try:
            route = '/scan_retrieval_codes/{}/files_ext/{}/download'.format(
                    apiid(srcode),
                    apiid(file))
            with dstpath.open('wb') as fd:
                await self._get(route, session, stream=fd)
        except aiohttp.ClientResponseError as e:
            logger.warning(e)
            if e.status == 403:
                raise IrmaError("Download forbidden")
