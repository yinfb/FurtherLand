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

from collections import OrderedDict
import json
import os
import re
import markdown
import hashlib
import random
import string
import functools
import time
import datetime
import feedgen.feed
import base64
import hmac
import hashlib
import urllib.parse


def slug_validation(*args, **kwargs):
    def decorator_wrapper(func):
        @functools.wraps(func)
        def wrapper(*func_args, **func_kwargs):
            valid_list = args[0]
            new_slug = []
            for number in range(0, len(valid_list)):
                value = self.value_validation(
                    valid_list[number], func_args[number])
                if value is not False:
                    new_slug.append(value)
                else:
                    raise aiohttp.web.HTTPNotFound
            return func(self, *new_slug, **func_kwargs)
        return wrapper
    return decorator_wrapper


def visitor_only(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.current_user:
            raise aiohttp.web.HTTPFound(self.next_url)
        return func(self, *args, **kwargs)
    return wrapper


def master_only(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.current_user:
            raise aiohttp.web.HTTPFound(self.login_url)
        return func(self, *args, **kwargs)
    return wrapper


class PlacesOfInterest:
    @asyncio.coroutine
    def prepare(self, furtherland, request):
        self.start_time = time.time()
        self.furtherland = furtherland
        self.request = request
        self.render_list = {}
        self.memories = self.furtherland.historial_records
        self.current_user = yield from self.get_current_user()
        self.config = yield from self.get_config()

        self.response_headers = []
        self.response_cookies = []

        self.body = b""

        self.login_url = "/management/checkin"

        self.next_url = self.get_arg("next", arg_type="link", default="/")

        self.remote_ip = self.request.headers.get(
            "X-Forwarded-For", self.request.headers.get(
                "X-Real-Ip", self.request.remote_ip))
        self.using_ssl = (self.request.headers.get(
            "X-Scheme", "http") == "https")
        if self.furtherland.melody.safe_land:
            self.set_header("strict-transport-security",
                            "max-age=39420000")

    @asyncio.coroutine
    def get_config(self):
        if not hasattr(self, "_config"):
            book = self.memories.select("Configs")
            book.find().length(0)
            yield from book.do()
            result = book.result()
            self._config = {}
            for value in result.values():
                self._config[value["_id"]] = value["value"]
        return self._config

    @asyncio.coroutine
    def get_current_user(self):
        if not hasattr(self, "_current_user"):
            user_id = self.get_scookie("user_id", arg_type="number")
            device_id = self.get_scookie("device_id", arg_type="hash")
            agent_auth = self.get_scookie("agent_auth", arg_type="hash")
            if not (user_id and device_id and agent_auth):
                self._current_user = None
            else:
                user = yield from self.get_user(_id=user_id)
                if self.hash((device_id + user["password"]),
                             "sha256") != agent_auth:
                    self._current_user = None
                else:
                    self._current_user = user
        return (self._current_user)

    def get_cookie(self, name):
        return self.request.cookies.get(name)

    def set_cookie(name, value, expires_days=None, secure=False,
                   httponly=False):
        if isinstance(name, str):
            name = name.encode("utf-8")
        elif not isinstance(name, bytes):
            raise ValueError

        if isinstance(value, str):
            name = value.encode("utf-8")
        elif not isinstance(value, bytes):
            raise ValueError

        if expires_days:
            max_age = expires_days * 86400
        else:
            max_age = None
        self.response_cookies.append({
            "name": name,
            "value": value,
            "max_age": max_age,
            "secure": secure,
            "httponly": httponly
        })

    def set_header(name, value):
        if isinstance(name, str):
            name = name.encode("utf-8")
        elif not isinstance(name, bytes):
            raise ValueError

        if isinstance(value, str):
            name = value.encode("utf-8")
        elif not isinstance(value, bytes):
            raise ValueError
        self.response_headers.append({
            "name": name,
            "value": value,
            "method": "set"
        })

    def add_header(name, value):
        if isinstance(name, str):
            name = name.encode("utf-8")
        elif not isinstance(name, bytes):
            raise ValueError

        if isinstance(value, str):
            name = value.encode("utf-8")
        elif not isinstance(value, bytes):
            raise ValueError
        self.response_headers.append({
            "name": name,
            "value": value,
            "method": "add"
        })

    def set_secure_cookie(self, name, value, expires_days=30, **kwargs):
        secret = self.surtherland.melody.secret

        timestamp = str(int(time.time())).encode("utf-8")
        if isinstance(value, str):
            value = value.encode("utf-8")
        elif not isinstance(value, bytes):
            raise ValueError
        value = base64.b64encode(value)

        if isinstance(name, str):
            name = name.encode("utf-8")
        elif not isinstance(name, bytes):
            raise ValueError

        def format_field(s):
            return ("%d:" % len(s)).encode("utf-8") + s
        to_sign = b"|".join([
            format_field(timestamp),
            format_field(name),
            format_field(value),
            b""])

        hash = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
        hash.update(to_sign)
        signature = hash.hexdigest().encode("utf-8")

        content = to_sign + signature
        self.set_cookie(name, content, expires_days=expires_days, **kwargs)

    def get_secure_cookie(self, name, max_age_days=31):
        secret = self.surtherland.melody.secret
        value = self.get_cookie(name)
        if not value:
            return None
        if isinstance(value, str):
            value = value.encode("utf-8")
        elif not isinstance(value, bytes):
            raise ValueError

        if isinstance(name, str):
            name = name.encode("utf-8")
        elif not isinstance(name, bytes):
            raise ValueError

        def _consume_field(s):
            length, _, rest = s.partition(b':')
            n = int(length)
            field_value = rest[:n]
            if rest[n:n + 1] != b'|':
                raise ValueError("malformed v2 signed value field")
            rest = rest[n + 1:]
            return field_value, rest
        try:
            timestamp, rest = _consume_field(value)
            name_field, rest = _consume_field(rest)
            value_field, passed_sig = _consume_field(rest)
        except ValueError:
            return None
        signed_string = value[:-len(passed_sig)]

        hash = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
        hash.update(signed_string)
        expected_sig = hash.hexdigest().encode("utf-8")

        if not hmac.compare_digest(passed_sig, expected_sig):
            return None
        if name_field != name:
            return None
        timestamp = int(timestamp)
        if timestamp < time.time() - max_age_days * 86400:
            return None
        try:
            return base64.b64decode(value_field)
        except Exception:
            return None

    def get_arg(self, arg, default=None, arg_type="origin"):
        result = None
        if self.request.method == "POST":
            result = self.request.POST.get(arg, None)
        if not result:
            result = self.request.GET.get(arg, None)

        if isinstance(result, bytes):
            result = str(result.decode())
        else:
            result = str(result)
        if (not result) or (result == "None"):
            return default
        return self.value_validation(arg_type, result)

    def get_scookie(self, arg, default=None, arg_type="origin"):
        result = self.get_secure_cookie(arg, max_age_days=181)
        if isinstance(result, bytes):
            result = str(result.decode())
        else:
            result = str(result)
        if (not result) or (result == "None"):
            return default
        return self.value_validation(arg_type, result)

    def set_scookie(self, arg, value="", expires_days=30, httponly=False):
        if not isinstance(value, str):
            value = str(value)
        if self.furtherland.melody.safe_land:
            secure = True
        else:
            secure = False
        self.set_secure_cookie(arg, value, expires_days,
                               httponly=httponly, secure=secure)

    def value_validation(self, arg_type, value):
        if arg_type == "origin":
            return value
        elif arg_type == "mail_address":
            mail_address = str(value)
            if re.match(
             r"^([\._+\-a-zA-Z0-9]+)@{1}([a-zA-Z0-9\-]+)\.([a-zA-Z0-9\-]+)$",
             mail_address) == None:
                return False
            else:
                return mail_address
        elif arg_type == "hash":
            hash_value = str(value)
            if re.match(r"^([a-zA-Z0-9]+)$", hash_value) == None:
                return False
            else:
                return hash_value
        elif arg_type == "slug":
            hash_value = str(value)
            if re.match(r"^([\-a-zA-Z0-9]+)$", hash_value) == None:
                return False
            else:
                return hash_value
        elif arg_type == "number":
            number = str(value)
            if re.match(r"^([\-\+0-9]+)$", number) == None:
                return False
            else:
                return int(number)
        elif arg_type == "boolean":
            boo = str(value).lower()
            if boo == "1" or boo == "true" or boo == "on":
                return True
            else:
                return False
        elif arg_type == "username":
            string = str(value)
            if re.match(r"^([ a-zA-Z]+)$", string) == None:
                return False
            else:
                return string
        elif arg_type == "link":
            link = str(value)
            if re.match(r"^(.*)$", link) == None:
                return False
            else:
                return link

    def hash(self, target, method):
        if not isinstance(target, bytes):
            target = target.encode(encoding="utf-8")

        if method == "sha1":
            return hashlib.sha1(target).hexdigest()
        elif method == "sha256":
            return hashlib.sha256(target).hexdigest()
        elif method == "md5":
            return hashlib.md5(target).hexdigest()

    @asyncio.coroutine
    def get_user(self, with_privacy=True, **kwargs):
        condition = list(kwargs.keys())[0]
        value = kwargs[condition]
        if condition != "user_list":
            if not hasattr(self, "_master_list"):
                self._master_list = {}

            if condition not in self._master_list.keys():
                self._master_list[condition] = {}

            if value not in self._master_list[condition].keys():
                book = self.memories.select("Masters")
                book.find({condition: value}).length(1)
                yield from book.do()
                self._master_list[condition][value] = book.result()

        user = {}
        user.update(self._master_list[condition][value])

        if not with_privacy:
            del user["password"]
            del user["otp_key"]
            del user["email"]

        return user

    def get_random(self, length):
        return "".join(random.sample(string.ascii_letters + string.digits,
                                     length))

    @asyncio.coroutine
    def get_class(self):
        pass

    @asyncio.coroutine
    def get_writing(self, only_published=True, **kwargs):
        book = self.memories.select("Writings")
        find_condition = {}
        if only_published is True:
            find_condition["publish"] = True
        if "class_id" in kwargs.keys():
            if kwargs["class_id"] != 0:
                find_condition["class_id"] = kwargs["class_id"]
            book.find(find_condition)
            book.sort([["time", False]])
            book.length(0, force_dict=True)
        elif "writing_list" in kwargs.keys():
            find_condition["_id"] = {"$in": kwargs["writing_list"]}
            book.find(find_condition, ["content"])
            book.sort([["time", False]])
            book.length(0, force_dict=True)
        elif "slug" in kwargs.keys():
            find_condition["slug"] = kwargs["slug"]
            book.find(find_condition)
        elif "id" in kwargs.keys():
            find_condition["_id"] = kwargs["id"]
            book.find(find_condition)
        yield from book.do()
        return book.result()

    @asyncio.coroutine
    def get_page(self, only_published=True, **kwargs):
        book = self.memories.select("Pages")
        find_condition = {}
        if only_published is True:
            find_condition["publish"] = True
        if "class_id" in kwargs.keys():
            if kwargs["class_id"] != 0:
                find_condition["class_id"] = kwargs["class_id"]
            book.find(find_condition)
            book.sort([["time", False]])
            book.length(0, force_dict=True)
        elif "slug" in kwargs.keys():
            find_condition["slug"] = kwargs["slug"]
            book.find(find_condition)
        elif "id" in kwargs.keys():
            find_condition["_id"] = kwargs["id"]
            book.find(find_condition)
        yield from book.do()
        return book.result()

    @asyncio.coroutine
    def get_reply(self, only_permitted=True, with_privacy=False, **kwargs):
        book = self.memories.select("Replies")
        ignore = None
        if not with_privacy:
            ignore = ["email", "ip"]
        find_condition = {}
        if only_permitted is True:
            find_condition["permit"] = True
        if "writing_id" in kwargs.keys():
            if kwargs["writing_id"] != 0:
                find_condition["writing_id"] = kwargs["writing_id"]
            book.find(find_condition, ignore)
            book.sort([["time", True]])
            book.length(0, force_dict=True)
        elif "id" in kwargs.keys():
            find_condition["_id"] = kwargs["id"]
            book.find(find_condition, ignore)
        yield from book.do()
        return book.result()

    @asyncio.coroutine
    def issue_id(self, working_type):
        book = self.memories.select("Counts")
        book.find_modify({"_id": working_type}, ["number"])
        yield from book.do()
        return int(book.result()["number"])

    def make_md(self, content, more=True):
        if not more:
            content = content.split("<!--more-->")[0]
        return markdown.markdown(content, extensions=["gfm"])

    def static_url(self, path, include_host=None, nutrition=True, **kwargs):
        if include_host:
            url = "//" + include_host + "/"
        else:
            url = "/"
        url += "spirit/"
        if nutrition:
            path = "nutrition/" + self.config["nutrition_type"] + "/" + path
        url += path
        return url

    def write(self, text):
        if self.body != b"":
            raise RuntimeError
        if isinstance(text, str):
            text = text.encode("utf-8")
        elif not isinstance(text, bytes):
            raise ValueError
        self.body = text

    def render(self, page, nutrition=True):
        if ("page_title" not in self.render_list.keys() and
           "origin_title" in self.render_list.keys()):
            self.render_list["page_title"] = (
                self.render_list["origin_title"] +
                " - " + self.config["site_name"])

        if not self.render_list.pop("__without_database", False):
            self.render_list["config"] = self.config
            self.render_list["FurtherLand"] = self.furtherland
            self.set_header("Furtherland-Used-Time",
                            int((time.time() - self.start_time) * 1000))

        self.xsrf_form_html()

        if nutrition:
            page = "nutrition/" + self.config["nutrition_type"] + "/" + page
        renderer = self.furtherland.prototype.get_template(page)
        self.write(renderer.render(self.render_list))

    @asyncio.coroutine
    def get_count(self):
        result = {}
        book = self.memories.select("Writings").count()
        yield from book.do()
        result["writings"] = book.result()
        book = self.memories.select("Replies").count()
        yield from book.do()
        result["replies"] = book.result()
        book = self.memories.select("Pages").count()
        yield from book.do()
        result["pages"] = book.result()
        return result

    def escape(self, item, item_type="html"):
        _XHTML_ESCAPE_RE = re.compile('[&<>"\']')
        _XHTML_ESCAPE_DICT = {'&': '&amp;', '<': '&lt;', '>': '&gt;',
                              '"': '&quot;', '\'': '&#39;'}

        if item_type == "html":
            return _XHTML_ESCAPE_RE.sub(
                lambda match: _XHTML_ESCAPE_DICT[match.group(0)],
                to_basestring(item))
        elif item_type == "url":
            return urllib.parse.quote_plus(item)
        else:
            raise HTTPError(500)

    def write_error(self, status_code, **kwargs):
        if status_code == 404:
            self.render_list["origin_title"] = "出错了！"
            self.render_list["slug"] = "not-found"
            self.render_list["sub_slug"] = ""
            self.render_list["current_content_id"] = 0
            self.render("model.htm")
        else:
            self.render_list["status_code"] = status_code
            self.render_list["error_message"] = self.furtherland.status_dict[
                status_code]
            self.render_list["__without_database"] = True
            self.render("management/error.htm")

    @asyncio.coroutine
    def responding(self):
        response = aiohttp.web.Response(self.body)
        for cookie in self.response_cookies:
            response.set_cookie(**cookie)
        for header in self.response_headers:
            if header["method"] == "set":
                response.headers[header["name"]] = header["value"]
            else:
                response.headers.add(header["name"], header["value"])
        return response

    def xsrf_form_html():
        pass


@asyncio.coroutine
def central_square(self):
    contents = yield from self.get_writing(class_id=0)
    for key in contents:
        contents[key]["author"] = yield from self.get_user(
            _id=contents[key]["author"], with_privacy=False)
        contents[key]["content"] = self.make_md(contents[key]["content"],
                                                more=False)
    self.render_list["contents"] = contents
    self.render_list["origin_title"] = "首页"
    self.render_list["slug"] = "index"
    self.render_list["sub_slug"] = ""
    self.render_list["current_content_id"] = 0
    self.render("model.htm")


class ConferenceHall:
    @asyncio.coroutine
    @slug_validation(["slug"])
    def get(self, writing_slug):
        writing = yield self.get_writing(slug=writing_slug)
        if not writing:
            raise HTTPError(404)
        writing["author"] = yield self.get_user(_id=writing["author"],
                                                with_privacy=False)
        writing["content"] = self.make_md(writing["content"])
        self.render_list["content"] = writing
        self.render_list["origin_title"] = writing["title"]
        self.render_list["slug"] = "writing"
        self.render_list["sub_slug"] = writing["slug"]
        self.render_list["current_content_id"] = writing["_id"]
        self.render("model.htm")


class MemorialWall:
    @asyncio.coroutine
    @slug_validation(["slug"])
    def get(self, page_slug):
        page = yield self.get_page(slug=page_slug)
        if not page:
            raise HTTPError(404)
        page["author"] = yield self.get_user(_id=page["author"],
                                             with_privacy=False)
        page["content"] = self.make_md(page["content"])
        self.render_list["content"] = page
        self.render_list["origin_title"] = page["title"]
        self.render_list["slug"] = "page"
        self.render_list["sub_slug"] = page["slug"]
        self.render_list["current_content_id"] = page["_id"]
        self.render("model.htm")


class NewsAnnouncement:
    @asyncio.coroutine
    def get(self):

        self.set_header("Content-Type", "application/xml; charset=\"utf-8\"")

        content = yield self.get_writing(class_id=0)

        fg = feedgen.feed.FeedGenerator()
        update_time = 0
        author = yield self.get_user(_id=1)
        fg.id(self.config["site_url"])
        fg.title(self.config["site_name"])
        fg.author({"name": author["username"], "email": author["email"]})
        fg.link(href=self.config["site_url"], rel="alternate")
        fg.link(href=self.config["site_url"] + "/feed.xml", rel="self")
        fg.language("zh-CN")
        fg.logo(self.config["site_url"] + "/spirit/favicon.jpg")

        for key in content.keys():
            current = fg.add_entry()
            current.id((self.config["site_url"] + "/writings/{0}.htm").format(
                content[key]["slug"])
            )
            current.link(href=(self.config[
                "site_url"] + "/writings/{0}.htm").format(
                    content[key]["slug"]))
            current.title(content[key]["title"])
            current.content(self.make_md(content[key]["content"]))
            if content[key]["time"] > update_time:
                update_time = content[key]["time"]
            current.updated(
                datetime.datetime.fromtimestamp(content[key]["time"]).replace(
                    tzinfo=datetime.timezone.utc))

            fg.updated(datetime.datetime.fromtimestamp(
                update_time).replace(
                    tzinfo=datetime.timezone.utc))

        atomfeed = fg.atom_str(pretty=True)
        self.write(atomfeed)


class HistoryLibrary:
    pass


class TerminalService:
    @asyncio.coroutine
    def post(self):
        action = self.get_arg("action", default=None, arg_type="link")
        if hasattr(self, action):
            yield getattr(self, action)()
        else:
            raise HTTPError(500)

    @asyncio.coroutine
    def load_index(self):
        contents = yield self.get_writing(class_id=0)
        for key in contents:
            contents[key]["author"] = yield self.get_user(
                _id=contents[key]["author"], with_privacy=False)
            contents[key]["content"] = contents[key]["content"].split(
                "<!--more-->")[0]
        self.finish(json.dumps(list(contents.values())))

    @asyncio.coroutine
    def load_writing(self):
        writing_slug = self.get_arg("slug", arg_type="slug")
        writing = yield self.get_writing(slug=writing_slug)
        if not writing:
            self.finish(json.dumps({
                "success": False,
                "reason": "notfound"
            }))
            return
        writing["author"] = yield self.get_user(_id=writing["author"],
                                                with_privacy=False)
        writing["success"] = True
        self.finish(json.dumps(writing))

    @asyncio.coroutine
    def load_page(self):
        page_slug = self.get_arg("slug", arg_type="slug")
        page = yield self.get_page(slug=page_slug)
        if not page:
            self.finish(json.dumps({
                "success": False,
                "reason": "notfound"
            }))
            return
        page["author"] = yield self.get_user(_id=page["author"],
                                             with_privacy=False)
        page["success"] = True
        self.finish(json.dumps(page))

    @asyncio.coroutine
    def load_reply(self):
        writing_id = self.get_arg("writing", arg_type="number")
        reply_id = self.get_arg("reply", arg_type="number")
        method = self.get_arg("method", arg_type="hash")
        if method == "list" and writing_id:
            result = yield self.get_reply(writing_id=writing_id)
        elif method == "single" and reply_id:
            result = yield self.get_reply(id=reply_id)
        else:
            raise HTTPError(500)
        self.finish(json.dumps(result))

    @asyncio.coroutine
    def new_reply(self):
        writing_id = self.get_arg("writing", arg_type="number")
        reply_id = self.get_arg("reply", arg_type="number")
        reply = OrderedDict()
        reply["writing_id"] = writing_id
        if not self.current_user:
            reply["master"] = False
            reply["name"] = self.get_arg("name", arg_type="origin")
            reply["email"] = self.get_arg("email", arg_type="mail_address")
            reply["homepage"] = self.get_arg("homepage", arg_type="link")
            if not (reply["name"] and reply["email"]):
                result = {
                    "success": False,
                    "reason": "incomplation"
                }
                self.finish(json.dumps(result))
                return
            reply["name"] = self.escape(reply["name"], item_type="html")
            reply["permit"] = False
        else:
            reply["master"] = True
            reply["name"] = self.current_user["username"]
            reply["email"] = self.current_user["email"]
            reply["homepage"] = self.current_user["homepage"]
            reply["permit"] = True
        reply["ip"] = self.remote_ip
        reply["time"] = int(time.time())
        reply["emailmd5"] = self.hash(reply["email"].lower(),
                                      "md5")
        content = self.escape(self.get_arg("content", arg_type="origin"),
                              item_type="html")
        content = re.sub(
            re.compile(r"(data:)", re.IGNORECASE), "data：", content)
        content = re.sub(
            re.compile(
                r"(javascript:)", re.IGNORECASE), "javascript：", content)
        reply["content"] = content
        reply["_id"] = yield self.issue_id("Replies")
        book = self.memories.select("Replies")
        book.add(reply)
        result = {}
        try:
            yield book.do()
            result["success"] = reply["master"]
            result["id"] = reply["_id"]
            if not reply["master"]:
                result["reason"] = "waitforcheck"
            if result["success"]:
                result.update(reply)
        except:
            result["success"] = False
            result["reason"] = "unkonwn"
        self.finish(json.dumps(result))


class IllustratePlace:
    @asyncio.coroutine
    @slug_validation(["hash"])
    def get(self, slug):
        size = self.get_arg("s", default=80, arg_type="number")
        default = self.get_arg("d", default=404, arg_type="hash")
        current_time = int(time.time())

        path = self.settings["static_path"] + "/public/avatar/" + slug
        if not os.path.exists(path):
            os.makedirs(path)

        file_path = path + "/" + str(size)
        if os.path.exists(file_path):
            book = self.memories.select("Publics")
            book.find(
                {"filename": str(size), "email_md5": slug, "type": "avatar"})
            yield book.do()
            avatar_info = book.result()
            if not avatar_info:
                os.remove(file_path)
                book.erase(
                    {
                        "filename": str(size),
                        "email_md5": slug,
                        "type": "avatar"
                    }
                )
                yield book.do()
            elif (current_time - avatar_info["time"]) <= (15 * 24 * 60 * 60):
                self.set_header(
                    "content-type", avatar_info["content_type"])
                with open(file_path, "rb") as f:
                    self.finish(f.read())
                return
            else:
                os.remove(file_path)
                book.erase(
                    {
                        "filename": str(size),
                        "email_md5": slug,
                        "type": "avatar"
                    }
                )
                yield book.do()

        client = tornado.httpclient.AsyncHTTPClient()
        link = (
            "https://secure.gravatar.com/avatar/" + slug + "?s=" +
            str(size) + "&d=" + str(default))
        response = yield client.fetch(link)
        if response.error:
            raise HTTPError(response.code)
        avatar = response.body
        content_type = response.headers.get("content-type")
        avatar_info = OrderedDict()
        avatar_info["time"] = current_time
        avatar_info["type"] = "avatar"
        avatar_info["content_type"] = content_type
        avatar_info["filename"] = str(size)
        avatar_info["filepath"] = file_path
        avatar_info["fileurl"] = None
        avatar_info["email_md5"] = slug
        avatar_info["_id"] = yield self.issue_id("Publics")

        with open(file_path, "wb") as f:
            f.write(avatar)

        book = self.memories.select("Publics")
        book.find(
            {"filename": str(size), "email_md5": slug, "type": "avatar"})
        yield book.do()
        if book.result():
            book.erase(
                {
                    "filename": str(size),
                    "email_md5": slug,
                    "type": "avatar"
                }
            )
            yield book.do()
        book.add(avatar_info)
        yield book.do()

        self.set_header("content-type", content_type)
        self.finish(avatar)


class LostAndFoundPlace:
    def get(self, *args, **kwargs):
        raise HTTPError(404)

    post = get
