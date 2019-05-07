#!/usr/bin/env python
# -*- coding:utf-8 -*-
# __author__ = "lyon"

import json
import sys
import six
import re
import random
import string
import inspect
import datetime
from importlib import import_module
from functools import wraps
from itertools import groupby
from flask.views import MethodView
from flask import Flask, request, jsonify, render_template, session, redirect, Blueprint

# Match the beginning of a named or unnamed group.
named_group_matcher = re.compile(r'\(\?P(<\w+>)')
unnamed_group_matcher = re.compile(r'\(')
http_method_names = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']


def replace_named_groups(pattern):
    r"""
    Find named groups in `pattern` and replace them with the group name. E.g.,
    1. ^(?P<a>\w+)/b/(\w+)$ ==> ^<a>/b/(\w+)$
    2. ^(?P<a>\w+)/b/(?P<c>\w+)/$ ==> ^<a>/b/<c>/$
    """
    named_group_indices = [
        (m.start(0), m.end(0), m.group(1))
        for m in named_group_matcher.finditer(pattern)
        ]
    # Tuples of (named capture group pattern, group name).
    group_pattern_and_name = []
    # Loop over the groups and their start and end indices.
    for start, end, group_name in named_group_indices:
        # Handle nested parentheses, e.g. '^(?P<a>(x|y))/b'.
        unmatched_open_brackets, prev_char = 1, None
        for idx, val in enumerate(list(pattern[end:])):
            # If brackets are balanced, the end of the string for the current
            # named capture group pattern has been reached.
            if unmatched_open_brackets == 0:
                group_pattern_and_name.append((pattern[start:end + idx], group_name))
                break

            # Check for unescaped `(` and `)`. They mark the start and end of a
            # nested group.
            if val == '(' and prev_char != '\\':
                unmatched_open_brackets += 1
            elif val == ')' and prev_char != '\\':
                unmatched_open_brackets -= 1
            prev_char = val

    # Replace the string for named capture groups with their group names.
    for group_pattern, group_name in group_pattern_and_name:
        pattern = pattern.replace(group_pattern, group_name)
    return pattern


def replace_unnamed_groups(pattern):
    r"""
    Find unnamed groups in `pattern` and replace them with '<var>'. E.g.,
    1. ^(?P<a>\w+)/b/(\w+)$ ==> ^(?P<a>\w+)/b/<var>$
    2. ^(?P<a>\w+)/b/((x|y)\w+)$ ==> ^(?P<a>\w+)/b/<var>$
    """
    unnamed_group_indices = [m.start(0) for m in unnamed_group_matcher.finditer(pattern)]
    # Indices of the start of unnamed capture groups.
    group_indices = []
    # Loop over the start indices of the groups.
    for start in unnamed_group_indices:
        # Handle nested parentheses, e.g. '^b/((x|y)\w+)$'.
        unmatched_open_brackets, prev_char = 1, None
        for idx, val in enumerate(list(pattern[start + 1:])):
            if unmatched_open_brackets == 0:
                group_indices.append((start, start + 1 + idx))
                break

            # Check for unescaped `(` and `)`. They mark the start and end of
            # a nested group.
            if val == '(' and prev_char != '\\':
                unmatched_open_brackets += 1
            elif val == ')' and prev_char != '\\':
                unmatched_open_brackets -= 1
            prev_char = val

    # Remove unnamed group matches inside other unnamed capture groups.
    group_start_end_indices = []
    prev_end = None
    for start, end in group_indices:
        if prev_end and start > prev_end or not prev_end:
            group_start_end_indices.append((start, end))
        prev_end = end

    if group_start_end_indices:
        # Replace unnamed groups with <var>. Handle the fact that replacing the
        # string between indices will change string length and thus indices
        # will point to the wrong substring if not corrected.
        final_pattern, prev_end = [], None
        for start, end in group_start_end_indices:
            if prev_end:
                final_pattern.append(pattern[prev_end:start])
            final_pattern.append(pattern[:start] + '<var>')
            prev_end = end
        final_pattern.append(pattern[prev_end:])
        return ''.join(final_pattern)
    else:
        return pattern


def simplify_regex(pattern):
    r"""
    Clean up urlpattern regexes into something more readable by humans. For
    example, turn "^(?P<sport_slug>\w+)/athletes/(?P<athlete_slug>\w+)/$"
    into "/<sport_slug>/athletes/<athlete_slug>/".
    """
    pattern = replace_named_groups(pattern)
    pattern = replace_unnamed_groups(pattern)
    # clean up any outstanding regex-y characters.
    pattern = pattern.replace('^', '').replace('$', '').replace('?', '')
    if not pattern.startswith('/'):
        pattern = '/' + pattern
    return pattern


def params_check(params):
    if not isinstance(params, (list, tuple)):
        raise TypeError('params type must be a list or tuple not %s.' % type(params))
    param_list = []
    for p in params:
        if isinstance(p, tuple):
            param_list.append(Param(*p))
        elif isinstance(p, Param):
            param_list.append(p)
        else:
            raise TypeError('api params type %s should be Param or tuple not %s.' % (p, type(p).__name__))
    return param_list


def import_string(dotted_path):
    """
    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.
    """
    try:
        module_path, class_name = dotted_path.rsplit('.', 1)
    except ValueError:
        module_path = None
        class_name = None
        msg = "%s doesn't look like a module path" % dotted_path
        six.reraise(ImportError, ImportError(msg), sys.exc_info()[2])

    module = import_module(module_path)

    try:
        return getattr(module, class_name)
    except AttributeError:
        msg = 'Module "%s" does not define a "%s" attribute/class' % (
            module_path, class_name)
        six.reraise(ImportError, ImportError(msg), sys.exc_info()[2])


def register_docs(url, params=None, headers=None, desc='', display=True, name=None):
    if params is None:
        params = []
    if headers is None:
        headers = []

    def decorator(view):
        method = view.__name__
        endpoint = name
        if endpoint is None:
            endpoint = view.__qualname__
        router.register(view=view, name=endpoint, url=url, params=params_check(params),
                        headers=params_check(headers),
                        desc=desc, method=method,
                        display=display)

        @wraps(view)
        def handler(*args, **kwargs):
            return view(*args, **kwargs)

        return handler

    return decorator


class Param(dict):
    """
    Parameters for building API documents.
    >>> Param('field_name', True, 'type', 'default_value', 'description')
    """

    def __init__(self, field_name, required, param_type, default='', description=''):
        """
        :param field_name: 字段名
        :param required: 是否必填
        :param param_type: 字段值类型, int, str, file
        :param default: 默认值
        :param description: 字段值描述
        """
        super(dict, self).__init__()
        self['field_name'] = field_name
        self['required'] = required
        self['param_type'] = param_type
        self['default'] = default
        self['description'] = description

    @property
    def kwargs(self):
        return {
            'field_name': self['field_name'],
            'required': self['required'],
            'param_type': self['param_type'],
            'default': self['default'],
            'description': self['description'],
        }


class Router(object):
    def __init__(self):
        self._registry = {}
        self.endpoints = []

    def register(self, **kwargs):
        view = kwargs['view']
        if self._registry.get(view.__module__) is None:
            self._registry[view.__module__] = [kwargs, ]
        else:
            self._registry[view.__module__].append(kwargs)


class Endpoint(object):
    def __init__(self, func, regex, method, headers, params, name_parent, desc=None):
        self.callback = func
        self.regex = regex
        self.method = method
        self.docstring = self.get_doc()
        self.desc = desc
        self.name_parent = name_parent.split('.')[-1]
        self.path = self.get_path()
        self.methods = [self.method, ]
        self.params = {method: params}
        self.headers = {method: headers}

    def __str__(self):
        return self.docstring

    @property
    def allowed_methods(self):
        methods = []
        for m in http_method_names:
            if m.upper() in self.methods:
                methods.append(m.upper())
        return methods

    @property
    def params_json(self):
        return self.get_params_json(self.params)

    @property
    def headers_json(self):
        return self.get_params_json(self.headers)

    def get_params_json(self, param_dict):
        data = {}
        for method, params in param_dict.items():
            tmp = []
            for p in params:
                tmp.append(p.kwargs)
            data[method] = tmp
        return json.dumps({'data': data})

    def get_path(self):
        return simplify_regex(self.regex)

    def get_doc(self):
        module = inspect.getmodule(self.callback)
        return inspect.getdoc(getattr(module, self.callback.__qualname__.split('.')[0]))


class Docs(object):
    def __init__(self,
                 app,
                 install_handler=None,
                 install_handler_name=None,
                 hide_docs=False,
                 default_headers=None,
                 default_params=None,
                 secret_key=None,
                 session_expiry_time=None,
                 username='admin',
                 password='admin',
                 **options):
        """

        :param app:
        :param install_handler:
        :param install_handler_name:
        :param hide_docs:
        :param default_headers:
        :param default_params:
        :param secret_key:
        :param session_expiry_time:
        :param username:
        :param password:
        :param options:
        """

        self.app = app
        self.install_handler = install_handler
        if not install_handler_name:
            install_handler_name = {}
        self.install_handler_name = install_handler_name
        self.hide_docs = hide_docs
        self.default_headers = default_headers
        self.default_params = default_params
        self.secret_key = str(secret_key) if secret_key else self.gen_secret_key()
        app.config["SECRET_KEY"] = self.secret_key
        self.session_expiry_time = 7 if not session_expiry_time else session_expiry_time
        app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=self.session_expiry_time)
        self.username = username
        self.password = password
        self.options = options
        if install_handler:
            for i in install_handler:
                import_string(i + '.__name__')
        if not hide_docs:
            self.add_docs_rule(app)

        if isinstance(app, Flask):
            self.sync_endpoint()
            self.add_rule(app)
            docs_page = Blueprint("flask_docs", __name__, static_folder='static', static_url_path='/flask_docs',
                                  template_folder='templates')
            app.register_blueprint(docs_page)

    def add_docs_rule(self, app):
        app.add_url_rule('/flask_docs', 'flask_docs_index', self.docs_index_view, methods=['GET'])
        app.add_url_rule('/flask_docs/login', 'flask_docs_login', self.docs_login_view, methods=['GET', 'POST'])
        app.add_url_rule('/flask_docs/logout', 'flask_docs_logout', self.docs_logout_view, methods=['GET'])

    def add_rule(self, app):
        for key in router._registry:
            for r in router._registry[key]:
                class_name = r['view'].__qualname__.split('.')[0]
                class_view = getattr(inspect.getmodule(r['view']), class_name)
                app.add_url_rule(r['url'], r['name'], class_view.as_view(r['name']))

    def gen_secret_key(self):
        s = string.ascii_letters + string.punctuation + string.digits
        return ''.join([random.choice(s) for _ in range(50)])

    def docs_index_view(self):
        if not session.get('username'):
            return redirect('/flask_docs/login')
        endpoints = {}
        router_endpoints = router.endpoints
        query = request.args.get('search', '')
        if query and router_endpoints:
            router_endpoints = [endpoint for endpoint in router_endpoints if query in endpoint.path]
        for key, group in groupby(router_endpoints, lambda x: x.name_parent):
            endpoints[key] = list(group)

        return render_template(
            'flask_docs/home.html',
            endpoints=endpoints,
        )

    def docs_login_view(self):
        error = ''
        if request.method == "POST":
            username = request.form.get('username')
            password = request.form.get('password')
            if username == self.username and password == self.password:
                session['username'] = username
                return redirect('/flask_docs')
            error = '用户名或密码错误!'
        return render_template('flask_docs/login.html', error=error)

    def docs_logout_view(self):
        if session.get('username'):
            session.pop('username')
        return redirect('/flask_docs/login')

    def sync_endpoint(self):
        for module, param in router._registry.items():
            for p in param:
                func, name, regex, params, headers, desc, display = p['view'], p['name'], p['url'], p[
                    'params'], p['headers'], p['desc'], p['display']
                default_params = []
                default_headers = []
                if self.default_params:
                    default_params = params_check(self.default_params)
                    params.extend(params_check(self.default_params))
                if self.default_headers:
                    default_headers = params_check(self.default_headers)
                    headers.extend(params_check(self.default_headers))
                view_name, method = func.__qualname__.split('.')

                if method not in http_method_names:
                    # method 不合法
                    raise type('HttpMethodError', (Exception,), {})('%s is not an HTTP method.' % method)

                method = method.upper()

                if display:
                    for endpoint in router.endpoints:
                        if endpoint.path == simplify_regex(regex):
                            endpoint.methods.append(method)
                            # 如果已经存在则进行覆盖
                            endpoint.params[method], endpoint.headers[method] = params, headers
                            break
                    else:
                        module = module.title()
                        if isinstance(self.install_handler_name, dict):
                            module = self.install_handler_name.get(module, module)
                        endpoint = Endpoint(func=func, regex=regex, method=method, headers=headers, params=params,
                                            name_parent=module, desc=desc)
                        if method != "OPTIONS":
                            endpoint.methods.append("OPTIONS")
                            endpoint.params["OPTIONS"], endpoint.headers[
                                "OPTIONS"] = default_params, default_headers
                        router.endpoints.append(endpoint)


class BaseHandler(MethodView):
    @property
    def data(self):
        if request.method == "GET" or request.method == "HEAD":
            return request.args
        elif request.method == "POST" or request.method == "DELETE" or \
                        request.method == "PUT" or request.method == "PATCH":
            return request.form
        else:
            return request.get_json()

    @property
    def request(self):
        return request

    def write(self, data):
        return jsonify(data)

    def options(self, *args, **kwargs):
        """
        Handles responding to requests for the OPTIONS HTTP verb.
        """
        return_data = {
            "name": self.__class__.__name__,
            "url": request.url,
            "description": self.__doc__,
            "renders": [
                "application/json",
                "text/html"
            ],
            "parses": [
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data"
            ]
        }
        return self.write({'return_code': 'success', 'return_data': return_data})


router = Router()
