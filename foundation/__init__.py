#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2015 Futur Solo
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import asyncio
import aiohttp
import aiohttp.web
import jinja2
import os

from . import place
from . import office
from . import memory as historial


class FurtherLand:
    status_dict = {
        100: b"Continue",
        101: b"Switching Protocols",
        102: b"Processing",
        200: b"OK",
        201: b"Created",
        202: b"Accepted",
        203: b"Non-Authoritative Information",
        204: b"No Content",
        205: b"Reset Content",
        206: b"Partial Content",
        207: b"Multi-Status",
        208: b"Already Reported",
        226: b"IM Used",
        300: b"Multiple Choices",
        301: b"Moved Permanently",
        302: b"Found",
        303: b"See Other",
        304: b"Not Modified",
        305: b"Use Proxy",
        307: b"Temporary Redirect",
        308: b"Permanent Redirect",
        400: b"Bad Request",
        401: b"Unauthorized",
        402: b"Payment Required",
        403: b"Forbidden",
        404: b"Not Found",
        405: b"Method Not Allowed",
        406: b"Not Acceptable",
        407: b"Proxy Authentication Required",
        408: b"Request Timeout",
        409: b"Conflict",
        410: b"Gone",
        411: b"Length Required",
        412: b"Precondition Failed",
        413: b"Request Entity Too Large",
        414: b"Request-URI Too Long",
        415: b"Unsupported Media Type",
        416: b"Requested Range Not Satisfiable",
        417: b"Expectation Failed",
        421: b"Misdirected Request",
        422: b"Unprocessable Entity",
        423: b"Locked",
        424: b"Failed Dependency",
        426: b"Upgrade Required",
        428: b"Precondition Required",
        429: b"Too Many Requests",
        431: b"Request Header Fields Too Large",
        500: b"Internal Server Error",
        501: b"Not Implemented",
        502: b"Bad Gateway",
        503: b"Service Unavailable",
        504: b"Gateway Timeout",
        505: b"HTTP Version Not Supported",
        506: b"Variant Also Negotiates",
        507: b"Insufficient Storage",
        508: b"Loop Detected",
        510: b"Not Extended",
        511: b"Network Authentication Required"
    }

    def __init__(self, melody):
        self.melody = melody
        self.loop = asyncio.get_event_loop()

        self.prototype = jinja2.Environment(
            loader=jinja2.FileSystemLoader(os.path.join(
                os.path.split(
                    os.path.realpath(self.melody.base))[0], "factory")))

        self.historial_records = historial.Records(self.melody.library)

        self.stage = aiohttp.web.Application(loop=self.loop,
                                             middlewares=[self.prepare])

        router = self.stage

        router.add_route("GET", "/", place.central_square)
        # router.add_route("GET", "/feed.xml", place.NewsAnnouncement)
        # router.add_route("GET", "/api", place.TerminalService)
        # router.add_route("GET", "/avatar/(.*)", place.IllustratePlace)
        # router.add_route("GET", "/writings/(.*).htm", place.ConferenceHall)
        # router.add_route("GET", "/pages/(.*).htm", place.MemorialWall)

        # router.add_route("GET", "/classes/(.*).htm", place.ClassesPlace)
        # router.add_route("GET", "/timeline", place.HistoryLibrary)

        # router.add_route("GET", "/management/checkin", office.CheckinOffice)
        # router.add_route("GET", "/management/checkout",
        #     office.CheckoutOffice)
        # router.add_route("GET", "/management/api", office.ActionOffice)
        # router.add_route("GET", "/management/(.*)/(.*)", office.MainOffice)
        # router.add_route("GET", "/management/(.*)", office.MainOffice)

    @asyncio.coroutine
    def prepare(self, stage, route):
        @asyncio.coroutine
        def wrapper(request):
            try:
                place_of_interest = place.PlacesOfInterest(self, request)
                yield from route(place_of_interest)
                response = yield from place_of_interest.responding()
            except aiohttp.web.HTTPNotFound:
                return
            return response
        return wrapper

    def rise(self):
        try:
            self.land = loop.run_until_complete(
                loop.create_server(self.stage.make_handler(),
                                   self.melody.listen_ip,
                                   self.melody.listen_port))

            print("FurtherLand has been risen on %s:%d." % (
                self.melody.listen_ip, self.melody.listen_port))

            self.loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.set()

    def set(self):
        try:
            self.land.close()
            self.loop.run_until_complete(self.land.wait_closed())
            self.loop.run_until_complete(self.stage.finish())
        except:
            pass
        loop.close()
        print("FurtherLand set.")

    def version(self):
        return "FurtherLand Sakihokori Edition"
