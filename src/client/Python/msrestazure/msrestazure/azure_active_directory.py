# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

import ast
import re
import time
try:
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs

import keyring
from oauthlib.oauth2 import BackendApplicationClient, LegacyApplicationClient
from oauthlib.oauth2.rfc6749.errors import (
    InvalidGrantError,
    MismatchingStateError,
    OAuth2Error,
    TokenExpiredError)
from requests import RequestException
import requests_oauthlib as oauth

from msrest.authentication import OAuthTokenAuthentication
from msrest.exceptions import TokenExpiredError as Expired
from msrest.exceptions import (
    AuthenticationError,
    raise_with_traceback)


def _build_url(uri, paths, scheme):
    """Combine URL parts.

    :param str uri: The base URL.
    :param list paths: List of strings that make up the URL.
    :param str scheme: The URL scheme, 'http' or 'https'.
    :rtype: str
    :return: Combined, formatted URL.
    """
    path = [str(p).strip('/') for p in paths]
    combined_path = '/'.join(path)
    parsed_url = urlparse(uri)
    replaced = parsed_url._replace(scheme=scheme)
    if combined_path:
        path = '/'.join([replaced.path, combined_path])
        replaced = replaced._replace(path=path)

    new_url = replaced.geturl()
    new_url = new_url.replace('///', '//')
    return new_url


def _http(uri, *extra):
    """Convert https URL to http.

    :param str uri: The base URL.
    :param str extra: Additional URL paths (optional).
    :rtype: str
    :return: An HTTP URL.
    """
    return _build_url(uri, extra, 'http')


def _https(uri, *extra):
    """Convert http URL to https.

    :param str uri: The base URL.
    :param str extra: Additional URL paths (optional).
    :rtype: str
    :return: An HTTPS URL.
    """
    return _build_url(uri, extra, 'https')


class AADMixin(OAuthTokenAuthentication):
    """Mixin for Authentication object.
    Provides some AAD functionality:
    - State validation
    - Token caching and retrieval
    - Default AAD configuration
    """
    _auth_endpoint = "//login.microsoftonline.com"
    _china_auth_endpoint = "//login.chinacloudapi.cn"
    _token_uri = "/oauth2/token"
    _auth_uri = "/oauth2/authorize"
    _tenant = "common"
    _resource = 'https://management.core.windows.net/'
    _china_resource = "https://management.core.chinacloudapi.cn/"
    _keyring = "AzureAAD"
    _case = re.compile('([a-z0-9])([A-Z])')

    def _configure(self, **kwargs):
        """Configure authentication endpoint.

        Optional kwargs may include:
            - china (bool): Configure auth for China-based service,
              default is 'False'.
            - tenant (str): Alternative tenant, default is 'common'.
            - auth_uri (str): Alternative authentication endpoint.
            - token_uri (str): Alternative token retrieval endpoint.
            - resource (str): Alternative authentication resource, default
              is 'https://management.core.windows.net/'.
            - verify (bool): Verify secure connection, default is 'True'.
            - keyring (str): Name of local token cache, default is 'AzureAAD'.
        """
        if kwargs.get('china'):
            auth_endpoint = self._china_auth_endpoint
            resource = self._china_resource
        else:
            auth_endpoint = self._auth_endpoint
            resource = self._resource

        tenant = kwargs.get('tenant', self._tenant)
        self.auth_uri = kwargs.get('auth_uri', _https(
            auth_endpoint, tenant, self._auth_uri))
        self.token_uri = kwargs.get('token_uri', _https(
            auth_endpoint, tenant, self._token_uri))
        self.verify = kwargs.get('verify', True)
        self.cred_store = kwargs.get('keyring', self._keyring)
        self.resource = kwargs.get('resource', resource)
        self.state = oauth.oauth2_session.generate_token()
        self.store_key = "{}_{}".format(
            self._auth_endpoint.strip('/'), self.store_key)

    def _check_state(self, response):
        """Validate state returned by AAD server.

        :param str response: URL returned by server redirect.
        :raises: ValueError if state does not match that of the request.
        :rtype: None
        """
        query = parse_qs(urlparse(response).query)
        if self.state not in query.get('state', []):
            raise ValueError(
                "State received from server does not match that of request.")

    def _convert_token(self, token):
        """Convert token fields from camel case.

        :param dict token: An authentication token.
        :rtype: dict
        """
        return {self._case.sub(r'\1_\2', k).lower(): v
                for k, v in token.items()}

    def _parse_token(self):
        # TODO: We could also check expires_on and use to update expires_in
        if self.token.get('expires_at'):
            countdown = float(self.token['expires_at']) - time.time()
            self.token['expires_in'] = countdown
        kwargs = {}
        if self.token.get('refresh_token'):
            kwargs['auto_refresh_url'] = self.token_uri
            kwargs['auto_refresh_kwargs'] = {'client_id': self.id,
                                             'resource': self.resource}
            kwargs['token_updater'] = self._default_token_cache
        return kwargs

    def _default_token_cache(self, token):
        """Store token for future sessions.

        :param dict token: An authentication token.
        :rtype: None
        """
        self.token = token
        keyring.set_password(self.cred_store, self.store_key, str(token))

    def _retrieve_stored_token(self):
        """Retrieve stored token for new session.

        :raises: ValueError if no cached token found.
        :rtype: dict
        :return: Retrieved token.
        """
        token = keyring.get_password(self.cred_store, self.store_key)
        if token is None:
            raise ValueError("No stored token found.")
        self.token = ast.literal_eval(str(token))
        self.signed_session()

    def signed_session(self):
        """Create token-friendly Requests session, using auto-refresh.
        Used internally when a request is made.

        :rtype: requests_oauthlib.OAuth2Session
        :raises: TokenExpiredError if token can no longer be refreshed.
        """
        kwargs = self._parse_token()
        try:
            new_session = oauth.OAuth2Session(
                self.id,
                token=self.token,
                **kwargs)
            return new_session
        except TokenExpiredError as err:
            raise_with_traceback(Expired, "", err)

    def clear_cached_token(self):
        """Clear any stored tokens.

        :raises: KeyError if failed to clear token.
        :rtype: None
        """
        try:
            keyring.delete_password(self.cred_store, self.store_key)
        except keyring.errors.PasswordDeleteError:
            raise_with_traceback(KeyError, "Unable to clear token.")


class AADRefreshMixin(object):
    """
    Additional token refresh logic
    """

    def refresh_session(self):
        """Return updated session if token has expired, attempts to
        refresh using newly acquired token.

        :rtype: requests.Session.
        """
        if self.token.get('refresh_token'):
            try:
                return self.signed_session()
            except Expired:
                pass
        self.set_token()
        return self.signed_session()


class AADTokenCredentials(AADMixin):
    """
    Credentials objects for AAD token retrieved through external process
    e.g. Python ADAL lib.

    Optional kwargs may include:
    - china (bool): Configure auth for China-based service,
      default is 'False'.
    - tenant (str): Alternative tenant, default is 'common'.
    - auth_uri (str): Alternative authentication endpoint.
    - token_uri (str): Alternative token retrieval endpoint.
    - resource (str): Alternative authentication resource, default
      is 'https://management.core.windows.net/'.
    - verify (bool): Verify secure connection, default is 'True'.
    - keyring (str): Name of local token cache, default is 'AzureAAD'.
    - cached (bool): If true, will not attempt to collect a token,
      which can then be populated later from a cached token.

    :param dict token: Authentication token.
    :param str client_id: Client ID, if not set, Xplat Client ID
     will be used.
    """

    def __init__(self, token, client_id=None, **kwargs):
        if not client_id:
            # Default to Xplat Client ID.
            client_id = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        super(AADTokenCredentials, self).__init__(client_id, None)
        self._configure(**kwargs)
        if not kwargs.get('cached'):
            self.token = self._convert_token(token)
            self.signed_session()

    @classmethod
    def retrieve_session(cls, client_id=None):
        """Create AADTokenCredentials from a cached token if it has not
        yet expired.
        """
        session = cls(None, None, client_id=client_id, cached=True)
        session._retrieve_stored_token()
        return session


class UserPassCredentials(AADRefreshMixin, AADMixin):
    """Credentials object for Headless Authentication,
    i.e. AAD authentication via username and password.

    Headless Auth requires an AAD login (no a Live ID) that already has
    permission to access the resource e.g. an organization account, and
    that 2-factor auth be disabled.

    Optional kwargs may include:
    - china (bool): Configure auth for China-based service,
      default is 'False'.
    - tenant (str): Alternative tenant, default is 'common'.
    - auth_uri (str): Alternative authentication endpoint.
    - token_uri (str): Alternative token retrieval endpoint.
    - resource (str): Alternative authentication resource, default
      is 'https://management.core.windows.net/'.
    - verify (bool): Verify secure connection, default is 'True'.
    - keyring (str): Name of local token cache, default is 'AzureAAD'.
    - cached (bool): If true, will not attempt to collect a token,
      which can then be populated later from a cached token.

    :param str username: Account username.
    :param str password: Account password.
    :param str client_id: Client ID, if not set, Xplat Client ID
     will be used.
    :param str secret: Client secret, only if required by server.
    """

    def __init__(self, username, password,
                 client_id=None, secret=None, **kwargs):
        if not client_id:
            # Default to Xplat Client ID.
            client_id = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        super(UserPassCredentials, self).__init__(client_id, None)
        self._configure(**kwargs)

        self.store_key += "_{}".format(username)
        self.username = username
        self.password = password
        self.secret = secret
        self.client = LegacyApplicationClient(client_id=self.id)
        if not kwargs.get('cached'):
            self.set_token()

    @classmethod
    def retrieve_session(cls, username, client_id=None):
        """Create ServicePrincipalCredentials from a cached token if it has not
        yet expired.
        """
        session = cls(username, None, client_id=client_id, cached=True)
        session._retrieve_stored_token()
        return session

    def _setup_session(self):
        """Create token-friendly Requests session.

        :rtype: requests_oauthlib.OAuth2Session
        """
        return oauth.OAuth2Session(client=self.client)

    def set_token(self):
        """Get token using Username/Password credentials.

        :raises: AuthenticationError if credentials invalid, or call fails.
        """
        session = self._setup_session()
        optional = {}
        if self.secret:
            optional['client_secret'] = self.secret
        try:
            token = session.fetch_token(self.token_uri, client_id=self.id,
                                        username=self.username,
                                        password=self.password,
                                        resource=self.resource,
                                        verify=self.verify,
                                        **optional)
        except (RequestException, OAuth2Error, InvalidGrantError) as err:
            raise_with_traceback(AuthenticationError, "", err)

        self.token = token


class ServicePrincipalCredentials(AADRefreshMixin, AADMixin):
    """Credentials object for Service Principle Authentication.
    Authenticates via a Client ID and Secret.

    Optional kwargs may include:
    - china (bool): Configure auth for China-based service,
      default is 'False'.
    - tenant (str): Alternative tenant, default is 'common'.
    - auth_uri (str): Alternative authentication endpoint.
    - token_uri (str): Alternative token retrieval endpoint.
    - resource (str): Alternative authentication resource, default
      is 'https://management.core.windows.net/'.
    - verify (bool): Verify secure connection, default is 'True'.
    - keyring (str): Name of local token cache, default is 'AzureAAD'.
    - cached (bool): If true, will not attempt to collect a token,
      which can then be populated later from a cached token.

    :param str client_id: Client ID.
    :param str secret: Client secret.
    """
    def __init__(self, client_id, secret, **kwargs):
        super(ServicePrincipalCredentials, self).__init__(client_id, None)
        self._configure(**kwargs)

        self.secret = secret
        self.client = BackendApplicationClient(self.id)
        if not kwargs.get('cached'):
            self.set_token()

    @classmethod
    def retrieve_session(cls, client_id):
        """Create ServicePrincipalCredentials from a cached token if it has not
        yet expired.
        """
        session = cls(client_id, None, cached=True)
        session._retrieve_stored_token()
        return session

    def _setup_session(self):
        """Create token-friendly Requests session.

        :rtype: requests_oauthlib.OAuth2Session
        """
        return oauth.OAuth2Session(self.id, client=self.client)

    def set_token(self):
        """Get token using Client ID/Secret credentials.

        :raises: AuthenticationError if credentials invalid, or call fails.
        """
        session = self._setup_session()
        try:
            token = session.fetch_token(self.token_uri, client_id=self.id,
                                        resource=self.resource,
                                        client_secret=self.secret,
                                        response_type="client_credentials",
                                        verify=self.verify)
        except (RequestException, OAuth2Error, InvalidGrantError) as err:
            raise_with_traceback(AuthenticationError, "", err)
        else:
            self.token = token


class InteractiveCredentials(AADMixin):
    """Credentials object for Interactive/Web App Authentication.
    Requires that an AAD Client be configured with a redirect URL.

    Optional kwargs may include:
    - china (bool): Configure auth for China-based service,
      default is 'False'.
    - tenant (str): Alternative tenant, default is 'common'.
    - auth_uri (str): Alternative authentication endpoint.
    - token_uri (str): Alternative token retrieval endpoint.
    - resource (str): Alternative authentication resource, default
      is 'https://management.core.windows.net/'.
    - verify (bool): Verify secure connection, default is 'True'.
    - keyring (str): Name of local token cache, default is 'AzureAAD'.
    - cached (bool): If true, will not attempt to collect a token,
      which can then be populated later from a cached token.

    :param str client_id: Client ID.
    :param str redirect: Redirect URL.
    """

    def __init__(self, client_id, redirect, **kwargs):
        super(InteractiveCredentials, self).__init__(client_id, None)
        self._configure(**kwargs)

        self.redirect = redirect
        if not kwargs.get('cached'):
            self.set_token()

    @classmethod
    def retrieve_session(cls, client_id, redirect):
        """Create InteractiveCredentials from a cached token if it has not
        yet expired.
        """
        session = cls(client_id, redirect, cached=True)
        session._retrieve_stored_token()
        return session

    def _setup_session(self):
        """Create token-friendly Requests session.

        :rtype: requests_oauthlib.OAuth2Session
        """
        return oauth.OAuth2Session(self.id,
                                   redirect_uri=self.redirect,
                                   state=self.state)

    def get_auth_url(self, msa=False, **additional_args):
        """Get URL to web portal for authentication.

        :param bool msa: Set to 'True' if authenticating with Live ID. Default
         is 'False'.
        :param additional_args: Set and additional kwargs for requrired AAD
         configuration: msdn.microsoft.com/en-us/library/azure/dn645542.aspx
        :rtype: Tuple
        :return: The URL for authentication (str), and state code that will
         be verified in the response (str).
        """
        if msa:
            additional_args['domain_hint'] = 'live.com'
        session = self._setup_session()
        auth_url, state = session.authorization_url(self.auth_uri,
                                                    resource=self.resource,
                                                    **additional_args)
        return auth_url, state

    def set_token(self, response_url):
        """Get token using Authorization Code from redirected URL.

        :param str response_url: The full redirected URL from successful
         authentication.
        :raises: AuthenticationError if credentials invalid, or call fails.
        """
        self._check_state(response_url)
        session = self._setup_session()

        if response_url.startswith(_http(self.redirect)):
            response_url = _https(response_url)
        elif not response_url.startswith(_https(self.redirect)):
            response_url = _https(self.redirect, response_url)
        try:
            token = session.fetch_token(self.token_uri,
                                        authorization_response=response_url,
                                        verify=self.verify)
        except (InvalidGrantError, OAuth2Error,
                MismatchingStateError, RequestException) as err:
            raise_with_traceback(AuthenticationError, "", err)
        else:
            self.token = token

################################################################################
# adal_authentication.py
import adal

from msrest.authentication import Authentication

#from azure.cli.core._util import CLIError

class AdalAuthentication(Authentication):#pylint: disable=too-few-public-methods

    def __init__(self, token_retriever):
        self._token_retriever = token_retriever

    def signed_session(self):
        session = super(AdalAuthentication, self).signed_session()

        try:
            scheme, token = self._token_retriever()
        except adal.AdalError as err:
            #pylint: disable=no-member
            if (hasattr(err, 'error_response') and ('error_description' in err.error_response)
                    and ('AADSTS70008:' in err.error_response['error_description'])):
                raise CLIError("Credentials have expired due to inactivity. Please run 'az login'")

            raise CLIError(err)

        header = "{} {}".format(scheme, token)
        session.headers['Authorization'] = header
        return session


# _profile.py
_AUTH_CTX_FACTORY = lambda authority, cache: adal.AuthenticationContext(authority, cache=cache)
_TOKEN_ENTRY_TOKEN_TYPE = 'tokenType'
_ACCESS_TOKEN = 'accessToken'

class Profile(object):
    def __init__(self, storage=None, auth_ctx_factory=None):
        self._storage = storage or ACCOUNT
        factory = auth_ctx_factory or _AUTH_CTX_FACTORY
        self._creds_cache = CredsCache(factory)
        self._subscription_finder = SubscriptionFinder(factory, self._creds_cache.adal_token_cache)
        env = get_env()
        self._management_resource_uri = env[ENDPOINT_URLS.MANAGEMENT]
        self._graph_resource_uri = env[ENDPOINT_URLS.ACTIVE_DIRECTORY_GRAPH_RESOURCE_ID]

    def find_subscriptions_on_login(self, #pylint: disable=too-many-arguments
                                    interactive,
                                    username,
                                    password,
                                    is_service_principal,
                                    tenant):
        self._creds_cache.remove_cached_creds(username)
        subscriptions = []
        if interactive:
            subscriptions = self._subscription_finder.find_through_interactive_flow(
                self._management_resource_uri)
        else:
            if is_service_principal:
                if not tenant:
                    raise CLIError('Please supply tenant using "--tenant"')

                subscriptions = self._subscription_finder.find_from_service_principal_id(
                    username, password, tenant, self._management_resource_uri)
            else:
                subscriptions = self._subscription_finder.find_from_user_account(
                    username, password, self._management_resource_uri)

        if not subscriptions:
            raise CLIError('No subscriptions found for this account.')

        if is_service_principal:
            self._creds_cache.save_service_principal_cred(username,
                                                          password,
                                                          tenant)
        if self._creds_cache.adal_token_cache.has_state_changed:
            self._creds_cache.persist_cached_creds()
        consolidated = Profile._normalize_properties(self._subscription_finder.user_id,
                                                     subscriptions,
                                                     is_service_principal,
                                                     ENV_DEFAULT)
        self._set_subscriptions(consolidated)
        return consolidated

    @staticmethod
    def _normalize_properties(user, subscriptions, is_service_principal, environment):
        consolidated = []
        for s in subscriptions:
            consolidated.append({
                _SUBSCRIPTION_ID: s.id.rpartition('/')[2],
                _SUBSCRIPTION_NAME: s.display_name,
                _STATE: s.state.value,
                _USER_ENTITY: {
                    _USER_NAME: user,
                    _USER_TYPE: _SERVICE_PRINCIPAL if is_service_principal else _USER
                    },
                _IS_DEFAULT_SUBSCRIPTION: False,
                _TENANT_ID: s.tenant_id,
                _ENVIRONMENT_NAME: environment
                })
        return consolidated

    def _set_subscriptions(self, new_subscriptions):
        existing_ones = self.load_cached_subscriptions()
        active_one = next((x for x in existing_ones if x.get(_IS_DEFAULT_SUBSCRIPTION)), None)
        active_subscription_id = active_one[_SUBSCRIPTION_ID] if active_one else None

        #merge with existing ones
        dic = collections.OrderedDict((x[_SUBSCRIPTION_ID], x) for x in existing_ones)
        dic.update((x[_SUBSCRIPTION_ID], x) for x in new_subscriptions)
        subscriptions = list(dic.values())

        if active_one:
            new_active_one = next(
                (x for x in new_subscriptions if x[_SUBSCRIPTION_ID] == active_subscription_id),
                None)

            for s in subscriptions:
                s[_IS_DEFAULT_SUBSCRIPTION] = False

            if not new_active_one:
                new_active_one = new_subscriptions[0]
            new_active_one[_IS_DEFAULT_SUBSCRIPTION] = True
        else:
            new_subscriptions[0][_IS_DEFAULT_SUBSCRIPTION] = True

        self._cache_subscriptions_to_local_storage(subscriptions)

    def set_active_subscription(self, subscription_id_or_name):
        subscriptions = self.load_cached_subscriptions()

        subscription_id_or_name = subscription_id_or_name.lower()
        result = [x for x in subscriptions
                  if subscription_id_or_name == x[_SUBSCRIPTION_ID].lower() or
                  subscription_id_or_name == x[_SUBSCRIPTION_NAME].lower()]

        if len(result) != 1:
            raise CLIError('The subscription of "{}" does not exist or has more than'
                           ' one match.'.format(subscription_id_or_name))

        for s in subscriptions:
            s[_IS_DEFAULT_SUBSCRIPTION] = False
        result[0][_IS_DEFAULT_SUBSCRIPTION] = True

        self._cache_subscriptions_to_local_storage(subscriptions)

    def logout(self, user_or_sp):
        subscriptions = self.load_cached_subscriptions()
        result = [x for x in subscriptions
                  if user_or_sp.lower() == x[_USER_ENTITY][_USER_NAME].lower()]
        subscriptions = [x for x in subscriptions if x not in result]

        #reset the active subscription if needed
        result = [x for x in subscriptions if x.get(_IS_DEFAULT_SUBSCRIPTION)]
        if not result and subscriptions:
            subscriptions[0][_IS_DEFAULT_SUBSCRIPTION] = True

        self._cache_subscriptions_to_local_storage(subscriptions)

        self._creds_cache.remove_cached_creds(user_or_sp)

    def logout_all(self):
        self._cache_subscriptions_to_local_storage({})
        self._creds_cache.remove_all_cached_creds()

    def load_cached_subscriptions(self):
        return self._storage.get(_SUBSCRIPTIONS) or []

    def _cache_subscriptions_to_local_storage(self, subscriptions):
        self._storage[_SUBSCRIPTIONS] = subscriptions

    def get_current_account_user(self):
        try:
            active_account = self.get_subscription()
        except CLIError:
            raise CLIError('There are no active accounts.')

        return active_account[_USER_ENTITY][_USER_NAME]

    def get_subscription(self, subscription_id=None):
        subscriptions = self.load_cached_subscriptions()
        if not subscriptions:
            raise CLIError('Please run login to setup account.')

        result = [x for x in subscriptions if (
            subscription_id is None and x.get(_IS_DEFAULT_SUBSCRIPTION)) or
                  (subscription_id == x.get(_SUBSCRIPTION_ID))]
        if len(result) != 1:
            raise CLIError('Please run "account set" to select active account.')
        return result[0]

    def get_login_credentials(self, for_graph_client=False, subscription_id=None):
        account = self.get_subscription(subscription_id)
        user_type = account[_USER_ENTITY][_USER_TYPE]
        username_or_sp_id = account[_USER_ENTITY][_USER_NAME]
        resource = self._graph_resource_uri if for_graph_client else self._management_resource_uri
        if user_type == _USER:
            token_retriever = lambda: self._creds_cache.retrieve_token_for_user(
                username_or_sp_id, account[_TENANT_ID], resource)
            auth_object = AdalAuthentication(token_retriever)
        else:
            token_retriever = lambda: self._creds_cache.retrieve_token_for_service_principal(
                username_or_sp_id, resource)
            auth_object = AdalAuthentication(token_retriever)

        return (auth_object,
                str(account[_SUBSCRIPTION_ID]),
                str(account[_TENANT_ID]))

    def get_installation_id(self):
        installation_id = self._storage.get(_INSTALLATION_ID)
        if not installation_id:
            import uuid
            installation_id = str(uuid.uuid1())
            self._storage[_INSTALLATION_ID] = installation_id
        return installation_id


class CredsCache(object):
    '''Caches AAD tokens and service principal secrets, and persistence will
    also be handled
    '''
    def __init__(self, auth_ctx_factory=None):
        self._token_file = os.path.expanduser('~/.azure/accessTokens.json')
        self._service_principal_creds = []
        self._auth_ctx_factory = auth_ctx_factory or _AUTH_CTX_FACTORY
        self.adal_token_cache = None
        self._load_creds()

    def persist_cached_creds(self):
        with os.fdopen(os.open(self._token_file, os.O_RDWR|os.O_CREAT|os.O_TRUNC, 0o600),
                       'w+') as cred_file:
            items = self.adal_token_cache.read_items()
            all_creds = [entry for _, entry in items]

            #trim away useless fields (needed for cred sharing with xplat)
            for i in all_creds:
                for key in TOKEN_FIELDS_EXCLUDED_FROM_PERSISTENCE:
                    i.pop(key, None)

            all_creds.extend(self._service_principal_creds)
            cred_file.write(json.dumps(all_creds))

        self.adal_token_cache.has_state_changed = False

    def retrieve_token_for_user(self, username, tenant, resource):
        authority = get_authority_url(tenant, ENV_DEFAULT)
        context = self._auth_ctx_factory(authority, cache=self.adal_token_cache)
        token_entry = context.acquire_token(resource, username, CLIENT_ID)
        if not token_entry:
            raise CLIError('Could not retrieve token from local cache, please run \'login\'.')

        if self.adal_token_cache.has_state_changed:
            self.persist_cached_creds()
        return (token_entry[_TOKEN_ENTRY_TOKEN_TYPE], token_entry[_ACCESS_TOKEN])

    def retrieve_token_for_service_principal(self, sp_id, resource):
        matched = [x for x in self._service_principal_creds if sp_id == x[_SERVICE_PRINCIPAL_ID]]
        if not matched:
            raise CLIError('Please run "account set" to select active account.')
        cred = matched[0]
        authority_url = get_authority_url(cred[_SERVICE_PRINCIPAL_TENANT], ENV_DEFAULT)
        context = self._auth_ctx_factory(authority_url, None)
        token_entry = context.acquire_token_with_client_credentials(resource,
                                                                    sp_id,
                                                                    cred[_ACCESS_TOKEN])
        return (token_entry[_TOKEN_ENTRY_TOKEN_TYPE], token_entry[_ACCESS_TOKEN])

    def _load_creds(self):
        if self.adal_token_cache is not None:
            return self.adal_token_cache
        all_entries = _load_tokens_from_file(self._token_file)
        self._load_service_principal_creds(all_entries)
        real_token = [x for x in all_entries if x not in self._service_principal_creds]
        self.adal_token_cache = adal.TokenCache(json.dumps(real_token))
        return self.adal_token_cache

    def save_service_principal_cred(self, service_principal_id, secret, tenant):
        entry = {
            _SERVICE_PRINCIPAL_ID: service_principal_id,
            _SERVICE_PRINCIPAL_TENANT: tenant,
            _ACCESS_TOKEN: secret
            }

        matched = [x for x in self._service_principal_creds
                   if service_principal_id == x[_SERVICE_PRINCIPAL_ID] and
                   tenant == x[_SERVICE_PRINCIPAL_TENANT]]
        state_changed = False
        if matched:
            if matched[0][_ACCESS_TOKEN] != secret:
                matched[0] = entry
                state_changed = True
        else:
            self._service_principal_creds.append(entry)
            state_changed = True

        if state_changed:
            self.persist_cached_creds()

    def _load_service_principal_creds(self, creds):
        for c in creds:
            if c.get(_SERVICE_PRINCIPAL_ID):
                self._service_principal_creds.append(c)
        return self._service_principal_creds

    def remove_cached_creds(self, user_or_sp):
        state_changed = False
        #clear AAD tokens
        tokens = self.adal_token_cache.find({_TOKEN_ENTRY_USER_ID: user_or_sp})
        if tokens:
            state_changed = True
            self.adal_token_cache.remove(tokens)

        #clear service principal creds
        matched = [x for x in self._service_principal_creds
                   if x[_SERVICE_PRINCIPAL_ID] == user_or_sp]
        if matched:
            state_changed = True
            self._service_principal_creds = [x for x in self._service_principal_creds
                                             if x not in matched]

        if state_changed:
            self.persist_cached_creds()

    def remove_all_cached_creds(self):
        #we can clear file contents, but deleting it is simpler
        _delete_file(self._token_file)

######################################################################
class AdalUserPassCredentials(Authentication):

    def __init__(self, username, password, client_id=None):
        super(AdalUserPassCredentials, self).__init__()
        if not client_id:
            # Default to Xplat Client ID.
            client_id = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        self.username = username
        self.password = password
        self.client_id = client_id
        # XXX typically comes through **kwargs
        self.authority = "/".join(['https://login.microsoftonline.com',
                                   'common'])
        self.resource = 'https://management.core.windows.net/'

    def signed_session(self):
        session = super(AdalUserPassCredentials, self).signed_session()
        context = adal.AuthenticationContext(self.authority)
        token_entry = context.acquire_token_with_username_password(
                self.resource, self.username, self.password, self.client_id)
        header = "{} {}".format(token_entry[_TOKEN_ENTRY_TOKEN_TYPE],
                                token_entry[_ACCESS_TOKEN])
        session.headers['Authorization'] = header
        return session
