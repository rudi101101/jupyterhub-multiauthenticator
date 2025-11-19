# Copyright © Idiap Research Institute <contact@idiap.ch>
#
# SPDX-License-Identifier: BSD-3-Clause
"""
Custom Authenticator to use multiple OAuth providers with JupyterHub

Example of configuration:

    c.MultiAuthenticator.authenticators = [
        {
            "authenticator_class": 'github',
            "url_prefix": '/github',
            "config": {
                'client_id': 'XXXX',
                'client_secret': 'YYYY',
                'oauth_callback_url': 'https://jupyterhub.example.com/hub/github/oauth_callback'
            }
        },
        {
            "authenticator_class": 'google',
            "url_prefix": '/google',
            "config": {
                'client_id': 'xxxx',
                'client_secret': 'yyyy',
                'oauth_callback_url': 'https://jupyterhub.example.com/hub/google/oauth_callback'
            }
        },
        {
            "authenticator_class": "pam",
            "url_prefix": "/pam",
        },
    ]

    c.JupyterHub.authenticator_class = 'multiauthenticator'

The same Authenticator class can be used several to support different providers.

"""
try:
    # Python < 3.10
    from importlib_metadata import entry_points
except ImportError:
    from importlib.metadata import entry_points
import warnings

from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join
from traitlets import List
from traitlets import Unicode
from traitlets import import_item

PREFIX_SEPARATOR = "_"


def _load_authenticator(authenticator_name):
    """Load an authenticator from a string

    Looks up authenticators entrypoint registration (e.g. 'github')
    or full import name ('jupyterhub.auth.PAMAuthenticator').

    Returns the Authenticator subclass.
    """
    for entry_point in entry_points(group="jupyterhub.authenticators"):
        if authenticator_name.lower() == entry_point.name.lower():
            return entry_point.load()
    return import_item(authenticator_name)


class URLScopeMixin:
    """Mixin class that adds the"""

    url_scope = ""

    def login_url(self, base_url):
        return super().login_url(url_path_join(base_url, self.url_scope))

    def logout_url(self, base_url):
        return super().logout_url(url_path_join(base_url, self.url_scope))

    def get_handlers(self, app):
        handlers = super().get_handlers(app)
        return [
            (url_path_join(self.url_scope, path), handler) for path, handler in handlers
        ]


def removeprefix(self: str, prefix: str) -> str:
    """PEP-0616 implementation to stay compatible with Python < 3.9"""
    if self.startswith(prefix):
        return self[len(prefix) :]
    else:
        return self[:]


class MultiAuthenticator(Authenticator):
    """Wrapper class that allows to use more than one authentication provider
    for JupyterHub"""

    authenticators = List(help="The subauthenticators to use", config=True)
    username_prefix = Unicode(
        help="Prefix to prepend to username",
        config=True,
        allow_none=True,
        default_value=None,
    )

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self._authenticators = []
        for entry in self.authenticators:
            if isinstance(entry, (list, tuple)):
                tuple_entry = entry
                entry = {
                    "authenticator_class": tuple_entry[0],
                    "url_prefix": tuple_entry[1],
                    "config": tuple_entry[2],
                }
                warnings.warn(
                    "Configuring subauthenticators with tuples is deprecated."
                    f" Use a dict like: {entry!r}",
                    DeprecationWarning,
                )

            authenticator_klass = entry["authenticator_class"]
            url_scope_authenticator = entry["url_prefix"]
            authenticator_configuration = entry.get("config", {})

            if isinstance(authenticator_klass, str):
                authenticator_klass = _load_authenticator(authenticator_klass)

            class WrapperAuthenticator(URLScopeMixin, authenticator_klass):
                url_scope = url_scope_authenticator

                @property
                def username_prefix(self):
                    prefix = getattr(self, "prefix", None)
                    if prefix is None:
                        prefix = f"{getattr(self, 'service_name', self.login_service)}{PREFIX_SEPARATOR}"
                    return self.normalize_username(prefix)

                async def authenticate(self, handler, data=None, **kwargs):
                    response = await super().authenticate(handler, data, **kwargs)
                    if response is None:
                        return None
                    elif type(response) == str:
                        return self.username_prefix + response
                    else:
                        response["name"] = self.username_prefix + response["name"]
                        return response

                def check_allowed(self, username, authentication=None):
                    if not username.startswith(self.username_prefix):
                        return False

                    return super().check_allowed(
                        removeprefix(username, self.username_prefix), authentication
                    )

                def check_blocked_users(self, username, authentication=None):
                    if not username.startswith(self.username_prefix):
                        return False

                    return super().check_blocked_users(
                        removeprefix(username, self.username_prefix), authentication
                    )

            service_name = authenticator_configuration.pop("service_name", None)

            authenticator = WrapperAuthenticator(
                parent=self, 
                add_new_table=False,
                **authenticator_configuration
            )

            # tambahkan ini
            try:
                from jupyterhub.orm import Base as JHBase
                db_url = str(self.parent.db_url) if hasattr(self.parent, "db_url") else None
                if db_url:
                    if hasattr(authenticator, "init_db"):
                        authenticator.init_db(db_url)
                        self.log.info(f"[MultiAuthenticator] init_db attached for {authenticator.login_service}")
                    else:
                        self.log.debug(f"[MultiAuthenticator] Skipping init_db for {authenticator.login_service} (no init_db method)")
                else:
                    self.log.warning("[MultiAuthenticator] Skipping init_db: db_url not found")
            except Exception as e:
                self.log.error(f"[MultiAuthenticator] init_db failed for {getattr(authenticator, 'login_service', str(authenticator))}: {e}")

            # # --- PATCH: inisialisasi database khusus untuk NativeAuthenticator ---
            # if hasattr(authenticator, "init_db") and getattr(authenticator, "db", None) is None:
            #     try:
            #         db_url = getattr(self, "db_url", None)
            #         if db_url is None:
            #             # fallback ke sqlite bawaan jupyterhub
            #             from jupyterhub.app import JupyterHub
            #             hub = JupyterHub.instance()
            #             if hub and hasattr(hub, "db_url"):
            #                 db_url = hub.db_url
            #             else:
            #                 db_url = "sqlite:///jupyterhub.sqlite"

            #         authenticator.init_db(db_url)
            #         self.log.info(f"[MultiAuthenticator] init_db sukses untuk {authenticator.__class__.__name__} ({db_url})")
            #     except Exception as e:
            #         self.log.error(f"[MultiAuthenticator] Gagal init_db untuk {authenticator.__class__.__name__}: {e}")
            # # -------------------------------------------------------------------

            if self.username_prefix is not None:
                authenticator.prefix = self.username_prefix
            elif service_name is not None:
                self.log.warning(
                    "service_name is deprecated, please create a subclass and set the login_service class variable"
                )
                if PREFIX_SEPARATOR in service_name:
                    raise ValueError(f"Service name cannot contain {PREFIX_SEPARATOR}")
                authenticator.service_name = service_name
            elif PREFIX_SEPARATOR in authenticator.login_service:
                raise ValueError(f"Login service cannot contain {PREFIX_SEPARATOR}")

            self._authenticators.append(authenticator)

    def get_custom_html(self, base_url):
        """Re-implementation generating one login button per configured authenticator

        Note: the html generated in this method will be passed through Jinja's template
        rendering, see the login implementation in JupyterHub's sources.
        """

        html = []
        for authenticator in self._authenticators:
            if hasattr(authenticator, "service_name"):
                login_service = getattr(authenticator, "service_name")
            else:
                login_service = authenticator.login_service

            url = authenticator.login_url(base_url)

            html.append(
                f"""
                <div class="service-login">
                  <a role="button" class='btn btn-jupyter btn-lg' href='{url}{{% if next is defined and next|length %}}?next={{{{next}}}}{{% endif %}}'>
                    Sign in with {login_service}
                  </a>
                </div>
                """
            )
        return "\n".join(html)

    def get_handlers(self, app):
        """Re-implementation that will return the handlers for all configured
        authenticators"""

        routes = []
        for _authenticator in self._authenticators:
            for path, handler in _authenticator.get_handlers(app):

                class WrapperHandler(handler):
                    """'Real' handler configured for each authenticator. This allows
                    to reuse the same authenticator class configured for different
                    services (for example GitLab.com, gitlab.example.com)
                    """

                    authenticator = _authenticator

                routes.append((path, WrapperHandler))
        return routes
