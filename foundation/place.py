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


from tornado.web import *
from tornado.gen import *
from tornado.escape import *
import re
import misaka
import hashlib
import base64
import random
import string
import functools
import mako.lookup
import mako.template
import time
import datetime
import feedgen.feed


def decorator_with_args(decorator_to_enhance):
    def decorator_maker(*args, **kwargs):
        def decorator_wrapper(func):
            return decorator_to_enhance(func, *args, **kwargs)
        return decorator_wrapper
    return decorator_maker


@decorator_with_args
def slug_validation(func, *args, **kwargs):
    @functools.wraps(func)
    def wrapper(self, *func_args, **func_kwargs):
        valid_list = args[0]
        new_slug = []
        for number in range(0, len(valid_list)):
            value = self.value_validation(
                valid_list[number], func_args[number])
            if value is not False:
                new_slug.append(value)
            else:
                raise HTTPError(404)
        return func(self, *new_slug, **func_kwargs)
    return wrapper


def visitor_only(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.current_user:
            self.redirect(self.next_url)
            return
        return func(self, *args, **kwargs)
    return wrapper


class PlacesOfInterest(RequestHandler):
    current_user = None

    @coroutine
    def prepare(self):
        self.start_time = time.time()
        self.furtherland = self.settings["further_land"]
        self.render_list = {}
        self.memories = self.settings["historial_records"]
        self.memories.initialize()
        self.current_user = yield self.get_current_user()
        self.current_visitor = yield self.get_current_visitor()
        self.config = yield self.get_config()

        self.next_url = self.get_arg("next", arg_type="link", default="/")
        self.remote_ip = self.request.headers.get(
            "X-Forwarded-For", self.request.headers.get(
                "X-Real-Ip", self.request.remote_ip))
        self.using_ssl = (self.request.headers.get(
            "X-Scheme", "http") == "https")
        self.safe_land = self.settings["safe_land"]
        if self.safe_land:
            self.set_header("strict-transport-security",
                            "max-age=39420000")

    @coroutine
    def get_config(self):
        if not hasattr(self, "_config"):
            book = self.memories.select("Configs")
            book.find().length(0)
            yield book.do()
            result = book.result()
            self._config = {}
            for value in result.values():
                self._config[value["_id"]] = value["value"]
        return self._config

    @coroutine
    def get_current_user(self):
        if not hasattr(self, "_current_user"):
            user_id = self.get_scookie("user_id", arg_type="number")
            device_id = self.get_scookie("device_id", arg_type="hash")
            agent_auth = self.get_scookie("agent_auth", arg_type="hash")
            if not (user_id and device_id and agent_auth):
                self._current_user = None
            else:
                user = yield self.get_user(_id=user_id)
                if self.hash((device_id + user["password"]),
                             "sha256") != agent_auth:
                    self._current_user = None
                else:
                    self._current_user = user
        return (self._current_user)

    def get_arg(self, arg, default=None, arg_type="origin"):
        result = RequestHandler.get_argument(self, arg, None)
        if isinstance(result, bytes):
            result = str(result.decode())
        else:
            result = str(result)
        if (not result) or (result == "None"):
            return default
        return self.value_validation(arg_type, result)

    def get_scookie(self, arg, default=None, arg_type="origin"):
        result = RequestHandler.get_secure_cookie(
            self, arg, None, max_age_days=181)
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
        if self.safe_land:
            secure = True
        else:
            secure = False
        RequestHandler.set_secure_cookie(
            self, arg, value, expires_days,
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

    def hash(self, target, method, b64=True):
        if not isinstance(target, bytes):
            target = target.encode(encoding="utf-8")

        if method == "sha1":
            return hashlib.sha1(target).hexdigest()
        elif method == "sha256":
            return hashlib.sha256(target).hexdigest()
        elif method == "md5":
            return hashlib.md5(target).hexdigest()

    @coroutine
    def get_user(self, **kwargs):
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
                yield book.do()
                self._master_list[condition][value] = (book.result())

        return self._master_list[condition][value]

    def get_random(self, length):
        return "".join(random.sample(string.ascii_letters + string.digits,
                                     length))

    @coroutine
    def get_class(self):
        pass

    @coroutine
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
        yield book.do()
        return book.result()

    @coroutine
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
        yield book.do()
        return book.result()

    @coroutine
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
        yield book.do()
        return book.result()

    @coroutine
    def issue_id(self, working_type):
        book = self.memories.select("Counts")
        book.find_modify({"_id": working_type}, ["number"])
        yield book.do()
        return int(book.result()["number"])

    def make_md(self, content, more=True):
        if not more:
            content = content.split("<!--more-->")[0]
        return misaka.html(content)

    def static_url(self, path, include_host=None, nutrition=True, **kwargs):
        if nutrition:
            path = "nutrition/" + self.config["nutrition_type"] + "/" + path
        return RequestHandler.static_url(
            self, path, include_host=include_host, **kwargs)

    def bower_url(self, path, include_host=None, **kwargs):
        path = "bower/" + path
        return RequestHandler.static_url(
            self, path, include_host=include_host, **kwargs)

    def render_string(self, filename, **kwargs):
        if filename not in self.furtherland.factory_preload.keys():
            self.furtherland.factory_preload[
                filename] = self.furtherland.factory.get_template(filename)
        if not kwargs.pop("__without_database", False):
            env_kwargs = {
                "handler": self,
                "request": self.request,
                "current_user": self.current_user,
                "current_visitor": self.current_visitor,
                "locale": self.locale,
                "_": self.locale.translate,
                "xsrf_form_html": self.xsrf_form_html,
                "reverse_url": self.application.reverse_url,
                "config": self.config,
                "static_url": self.static_url,
                "bower_url": self.bower_url,
                "FurtherLand": self.furtherland,
                "used_time": int((time.time() - self.start_time) * 1000)
            }
        else:
            env_kwargs = {}
        env_kwargs.update(kwargs)
        self.xsrf_form_html()
        return self.furtherland.factory_preload[filename].render(**env_kwargs)

    def render(self, page, nutrition=True):
        if ("page_title" not in self.render_list.keys() and
           "origin_title" in self.render_list.keys()):
            self.render_list["page_title"] = (
                self.render_list["origin_title"] +
                " - " + self.config["site_name"])
        if nutrition:
            page = "nutrition/" + self.config["nutrition_type"] + "/" + page
        self.finish(self.render_string(page, **self.render_list))

    @coroutine
    def get_count(self):
        result = {}
        book = self.memories.select("Writings").count()
        yield book.do()
        result["writings"] = book.result()
        book = self.memories.select("Replies").count()
        yield book.do()
        result["replies"] = book.result()
        book = self.memories.select("Pages").count()
        yield book.do()
        result["pages"] = book.result()
        return result

    def escape(self, item, item_type="html"):
        if item_type == "html":
            return xhtml_escape(item)
        elif item_type == "url":
            return url_escape(item)
        else:
            raise HTTPError(500)

    def write_error(self, status_code, **kwargs):
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            self.set_header("Content-Type", "text/plain")
            for line in traceback.format_exception(*kwargs["exc_info"]):
                self.write(line)
            self.finish()
        else:
            if status_code == 404:
                self.render_list["origin_title"] = "出错了！"
                self.render("404.htm")
            else:
                self.render_list["status_code"] = status_code
                self.render_list["error_message"] = self._reason
                self.finish(
                    self.render_string(
                        "management/error.htm",
                        __without_database=True,
                        **self.render_list))

    @coroutine
    def get_current_visitor(self):
        book = self.memories.select("Visitors")
        book.find({
            "_id": self.get_scookie("visitor_id", arg_type="number"),
            "visitor_auth": self.get_scookie("visitor_auth",
                                             arg_type="hash")
        })
        yield book.do()
        result = book.result()
        if result:
            return result
        self.clear_cookie("visitor_id")
        self.clear_cookie("visitor_auth")
        return None

    @coroutine
    def checkin_visitor(self, oauth_type, visitor):
        book = self.memories.select("Visitors")
        if oauth_type is "github":
            book.find({
                "oauth_type": "github",
                "oauth_id": visitor["id"]
            })
            yield book.do()
            result = book.result()
            if result:
                return {
                    "visitor_id": result["_id"],
                    "visitor_auth": result["visitor_auth"]
                }
            visitor_info = {
                "_id": (yield self.issue_id("Visitors")),
                "oauth_type": "github",
                "oauth_id": visitor["id"],
                "login_name": visitor.get("login"),
                "access_token": visitor.get("access_token"),
                "avatar_url": visitor.get("avatar_url"),
                "name": visitor.get("name"),
                "email": visitor.get("email"),
                "homepage": visitor.get("blog"),
                "visitor_auth": self.get_random(32)
            }
        book.add(visitor_info)
        yield book.do()
        return {
            "visitor_id": visitor_info["_id"],
            "visitor_auth": visitor_info["visitor_auth"]
        }


class CentralSquare(PlacesOfInterest):
    @coroutine
    def get(self):
        self.render_list["contents"] = yield self.get_writing(class_id=0)
        for key in self.render_list["contents"]:
            self.render_list["contents"][key]["author"] = yield self.get_user(
                _id=self.render_list["contents"][key]["author"])
            self.render_list["contents"][key]["content"] = self.make_md(
                self.render_list["contents"][key]["content"], more=False)
        self.render_list["origin_title"] = "首页"
        self.render("index.htm")


class ConferenceHall(PlacesOfInterest):
    @coroutine
    @slug_validation(["slug"])
    def get(self, writing_slug):
        writing = yield self.get_writing(slug=writing_slug)
        if not writing:
            raise HTTPError(404)
        writing["author"] = yield self.get_user(_id=writing["author"])
        writing["content"] = self.make_md(writing["content"])
        self.render_list["writing"] = writing
        self.render_list["origin_title"] = writing["title"]
        self.render("writings.htm")


class MemorialWall(PlacesOfInterest):
    @coroutine
    @slug_validation(["slug"])
    def get(self, page_slug):
        page = yield self.get_page(slug=page_slug)
        if not page:
            raise HTTPError(404)
        page["author"] = yield self.get_user(_id=page["author"])
        page["content"] = self.make_md(page["content"])
        self.render_list["page"] = page
        self.render_list["origin_title"] = page["title"]
        self.render("pages.htm")


class NewsAnnouncement(PlacesOfInterest):
    @coroutine
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


class HistoryLibrary(PlacesOfInterest):
    pass


class LostAndFoundPlace(PlacesOfInterest):
    def get(self, *args, **kwargs):
        raise HTTPError(404)

    post = get
