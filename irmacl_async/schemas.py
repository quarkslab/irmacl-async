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

import datetime
import enum

from marshmallow import fields, Schema, post_load


__all__ = [
    "Paginated",
    "IrmaTag",
    "IrmaTagSchema",
    "IrmaFileExt",
    "IrmaFileExtSchema",
    "IrmaFileInfo",
    "IrmaFileInfoSchema",
    "IrmaProbeResultSchema",
    "IrmaProbeListSchema",
    "IrmaFileResultSchema",
    "IrmaScan",
    "IrmaScanSchema",
    "IrmaAntivirusResultSchema",
    "apiid",
]


class Paginated(type):
    def __new__(_, enclosed, **extra):
        class Page(Schema):
            offset = fields.Integer()
            limit = fields.Integer()
            total = fields.Integer()
            # IRMA API is non consistent about the field it puts results in
            data = fields.Nested(enclosed, many=True, **extra)
            items = fields.Nested(enclosed, many=True, **extra)

            @post_load
            def make_object(self, data):
                return data

        return Page


class IrmaTagSchema(Schema):
    id = fields.Integer()
    text = fields.String()

    @post_load
    def make_object(self, data):
        return IrmaTag(**data)


class IrmaFileInfoSchema(Schema):
    size = fields.Integer()
    sha256 = fields.String()
    sha1 = fields.String()
    md5 = fields.String()
    timestamp_first_scan = fields.Number()
    timestamp_last_scan = fields.Number()
    mimetype = fields.String()
    tags = fields.Nested(IrmaTagSchema, many=True)

    @post_load
    def make_object(self, data):
        return IrmaFileInfo(**data)


class IrmaProbeListSchema(Schema):
    total = fields.Integer()
    data = fields.List(fields.String)

    @post_load
    def make_object(self, data):
        return data["data"]


class IrmaProbeResultSchema(Schema):
    version = fields.String()
    status = fields.Integer()
    duration = fields.Float()
    results = fields.Field()
    plateform = fields.String()
    error = fields.String(allow_none=True)


class IrmaAntivirusResultSchema(IrmaProbeResultSchema):
    virus_database_version = fields.String()
    database = fields.Dict(
        keys=fields.String,
        values=fields.Dict())


class IrmaProbesResultSchema(Schema):
    antivirus = fields.Dict(
        keys=fields.String,
        values=fields.Nested(IrmaAntivirusResultSchema))
    external = fields.Dict(
        keys=fields.String,
        values=fields.Nested(IrmaProbeResultSchema))
    metadata = fields.Dict(
        keys=fields.String,
        values=fields.Nested(IrmaProbeResultSchema))


class IrmaFileExtSchema(Schema):
    file_infos = fields.Nested(IrmaFileInfoSchema)
    status = fields.Integer(allow_none=True)
    probes_finished = fields.Integer()
    probes_total = fields.Integer()
    scan_id = fields.UUID(allow_none=True)
    name = fields.String()
    parent_file_sha256 = fields.String()
    result_id = fields.UUID()
    id = fields.UUID()
    file_sha256 = fields.String()
    scan_date = fields.Integer(allow_none=True)
    # scan_date = fields.Date()
    submitter = fields.String()
    parent_file_sha256 = fields.String(allow_none=True)
    other_results = fields.Nested(
        'self', only=("external_id", "scan_date", "status"), many=True)
    probe_results = fields.Nested(IrmaProbesResultSchema)

    @post_load
    def make_object(self, data):
        return IrmaFileExt(**data)


class IrmaScanSchema(Schema):
    results = fields.Nested(
        IrmaFileExtSchema, many=True, exclude=('probe_results', 'file_infos'))
    status = fields.Integer()
    probes_finished = fields.Integer()
    date = fields.Number()
    # date = fields.Date()
    probes_total = fields.Integer()
    id = fields.UUID()
    force = fields.Boolean()
    resubmit_files = fields.Boolean()
    mimetype_filtering = fields.Boolean()
    results = fields.Nested(IrmaFileExtSchema, many=True)

    @post_load
    def make_object(self, data):
        return IrmaScan(**data)


class IrmaFileResultSchema(Paginated(
        IrmaFileExtSchema, exclude=('probe_results', 'files_infos'))):
    file_infos = fields.Nested(IrmaFileInfoSchema)

    @post_load
    def make_object(self, data):
        return data


def apiid(obj):  # pragma: no cover
    if isinstance(obj, (IrmaTag, IrmaFileInfo, IrmaFileExt, IrmaScan)):
        return obj.id
    else:
        return obj


def timestamp_to_date(timestamp):
    if timestamp is None:
        return None
    date = datetime.datetime.fromtimestamp(int(timestamp))
    return date.strftime('%Y-%m-%d %H:%M:%S')


#   OBJECTS   #################################################################

class IrmaScanStatus(enum.IntEnum):
    empty = 0
    ready = 10
    uploaded = 20
    launched = 30
    processed = 40
    finished = 50
    flushed = 60
    # cancel
    cancelling = 100
    cancelled = 110
    # errors
    error = 1000
    # Probes 101x
    error_probe_missing = 1010
    error_probe_na = 1011
    # FTP 102x
    error_ftp_upload = 1020


class IrmaTag:

    def __init__(self, id, text):
        self.id = id
        self.text = text

    def __repr__(self):
        return "Tag.{} [{}]".format(self.id, self.text)

    def __str__(self):
        return "Tag." + self.text

    def __eq__(self, other):
        return self.id == other.id and self.text == other.text

    def __neq__(self, other):
        return not (self == other)


class IrmaScan:
    """ IrmaScan
    Description for class

    :ivar id: id of the scan
    :ivar status: int (one of IrmaScanStatus)
    :ivar probes_finished: number of finished probes analysis for current scan
    :ivar probes_total: number of total probes analysis for current scan
    :ivar date: scan creation date
    :ivar force: force a new analysis or not
    :ivar resubmit_files: files generated by the probes should be analyzed
        or not
    :ivar mimetype_filtering: probes list should be decided based on files
        mimetype or not
    :ivar results: list of IrmaFileExt objects
    """

    def __init__(self, id, status=None, probes_finished=None,
                 probes_total=None, date=None, force=None, resubmit_files=None,
                 mimetype_filtering=None, results=None):
        self.id = str(id)
        self.status = status
        self.probes_finished = probes_finished
        self.probes_total = probes_total
        self.date = date
        self.force = force
        self.resubmit_files = resubmit_files
        self.mimetype_filtering = mimetype_filtering
        self.results = results or []

    def is_launched(self):
        return self.status == IrmaScanStatus.launched

    def is_finished(self):
        return self.status == IrmaScanStatus.finished

    @property
    def pstatus(self):
        return IrmaScanStatus(self.status).name

    @property
    def pdate(self):
        return timestamp_to_date(self.date)

    def __str__(self):
        ret = "Scanid: {0}\n".format(self.id)
        ret += "Status: {0}\n".format(self.pstatus)
        ret += "Probes finished: {0}\n".format(self.probes_finished)
        ret += "Probes Total: {0}\n".format(self.probes_total)
        ret += "Date: {0}\n".format(self.pdate)
        ret += "Options: Force [{0}] ".format(self.force)
        ret += "Resubmit [{0}]\n".format(self.resubmit_files)
        ret += "Mimetype [{0}] ".format(self.mimetype_filtering)
        ret += "Results: {0}\n".format(self.results)
        return ret

    def __repr__(self):
        return "Scan." + self.id

    def __eq__(self, other):
        return self.id == other.id

    def __neq__(self, other):
        return not (self == other)


class IrmaFileExt:
    """ IrmaFileExt
    Description for class

    :ivar status: int
        (0 means clean 1 at least one AV report this file as a virus)
    :ivar probes_finished: number of finished probes analysis for current file
    :ivar probes_total: number of total probes analysis for current file
    :ivar scan_id: id of the scan
    :ivar name: file name
    :ivar path: file path (as sent during upload or resubmit)
    :ivar id: id of this file_ext (specific results for this file and this
    scan)
     used to fetch probe_results through scan_proberesults helper function
    :ivar file_infos: IrmaFileInfo object
    :ivar probe_results: list of IrmaProbeResults objects
    """

    def __init__(self, id=None, result_id=None, external_id=None, status=None,
                 probes_finished=None, probes_total=None, scan_id=None,
                 scan_date=None, name=None, file_sha256=None,
                 parent_file_sha256=None, submitter=None, probe_results=None,
                 file_infos=None, other_results=None):
        self.status = status
        self.probes_finished = probes_finished
        self.probes_total = probes_total
        # convert from UUID to a string
        self.scan_id = str(scan_id) if scan_id is not None else None
        self.scan_date = scan_date
        self.name = name
        self.file_sha256 = file_sha256
        self.parent_file_sha256 = parent_file_sha256
        id = id or result_id or external_id
        self.id = str(id) if id is not None else None
        self.submitter = submitter
        if probe_results is not None:
            self.probe_results = probe_results
        if file_infos is not None:
            self.file_infos = file_infos

    @property
    def pscan_date(self):
        return timestamp_to_date(self.scan_date)

    def to_json(self):
        return IrmaFileExtSchema().dumps(self).data

    def __str__(self):
        ret = "id: {0}\n".format(self.id)
        ret += "Status: {0}\n".format(self.status)
        ret += "Probes finished: {0}\n".format(self.probes_finished)
        ret += "Probes Total: {0}\n".format(self.probes_total)
        ret += "Scanid: {0}\n".format(self.scan_id)
        ret += "Scan Date: {0}\n".format(self.pscan_date)
        ret += "Filename: {0}\n".format(self.name)
        ret += "SHA256: {0}\n".format(self.file_sha256)
        ret += "ParentFile SHA256: {0}\n".format(self.parent_file_sha256)
        if hasattr(self, 'file_infos'):
            ret += "FileInfo: \n{0}\n".format(self.file_infos)
        if hasattr(self, 'probe_results'):
            ret += "Results: {0}\n".format(self.probe_results)
        return ret

    def __repr__(self):
        return "FileExt." + self.id


class IrmaFileInfo:

    def __init__(self, sha256, *, size=None, sha1=None, md5=None,
                 timestamp_first_scan=None, timestamp_last_scan=None,
                 mimetype=None, tags=None):
        self.sha256 = sha256
        self.size = size
        self.sha1 = sha1
        self.md5 = md5
        self.timestamp_first_scan = timestamp_first_scan
        self.timestamp_last_scan = timestamp_last_scan
        self.mimetype = mimetype
        self.tags = tags or []

    @property
    def id(self):
        return self.sha256

    @property
    def pdate_first_scan(self):
        try:
            return timestamp_to_date(self.timestamp_first_scan)
        except TypeError:
            return None

    @property
    def pdate_last_scan(self):
        try:
            return timestamp_to_date(self.timestamp_last_scan)
        except TypeError:
            return None

    def __repr__(self):
        return "File." + self.id

    def __str__(self):
        ret = "Size: {0}\n".format(self.size)
        ret += "Sha1: {0}\n".format(self.sha1)
        ret += "Sha256: {0}\n".format(self.sha256)
        ret += "Md5: {0}s\n".format(self.md5)
        ret += "First Scan: {0}\n".format(self.pdate_first_scan)
        ret += "Last Scan: {0}\n".format(self.pdate_last_scan)
        ret += "Mimetype: {0}\n".format(self.mimetype)
        ret += "Tags: {0}\n".format(self.tags)
        return ret
