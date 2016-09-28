import requests
import requests_oauthlib

from msrest.authentication import OAuthTokenAuthentication


class AADMixin(OAuthTokenAuthentication):

    auth_uri: str
    token_uri: str
    verify: bool
    cred_store: str
    resource: str
    state: requests_oauthlib.oauth2_session.generate_token() // XXX
    store_key: str
    token: dict
    # OAuthTokenAuthentication
    scheme: str
    id: str

    def signed_session(self) -> requests_oauthlib.OAuth2Session: ...
    def clear_cached_token(self) -> None: ...

class AADRefreshMixin(object):

    token

    def refresh_session(self) -> requests.Session: ...

class AADTokenCredentials(AADMixin):

    token

    def __init__(self, token: dict, client_id: str = ..., **kwargs):
        """"Optional kwargs may include:
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
        """
    @classmethod
    def retrieve_session(cls, client_id: str = ...) -> "AADTokenCredentials":
        ...

class UserPassCredentials(AADRefreshMixin, AADMixin):

    store_key
    username
    password
    secret
    client
    id
    resource
    verify
    token

    def __init__(self, username: str, password: str, client_id: str = ...,
                 secret: str = ..., **kwargs):
        """Optional kwargs may include:
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
            which can then be populated later from a cached token
        """
    @classmethod
    def retrieve_session(cls, username: str,
                         client_id: str = ...) -> "UserPassCredentials": ...
    def set_token(self) -> None: ...

class ServicePrincipalCredentials(AADRefreshMixin, AADMixin):

    secret
    client
    id
    resource
    secret
    verify
    token

    def __init__(self, client_id: str, secret: str, **kwargs):
        """Optional kwargs may include:
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
        """
    @classmethod
    def retrieve_session(cls, client_id: str) -> "ServicePrincipalCredentials":
        ...
    def set_token(self) -> None: ...

class InteractiveCredentials(AADMixin):

    redirect
    id
    state
    auth_uri
    resource
    token_uri
    token

    def __init__(self, client_id: str, redirect: str, **kwargs):
        """Optional kwargs may include:
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
        """
    @classmethod
    def retrieve_session(cls, client_id: str,
                         redirect: str) -> "InteractiveCredentials": ...
    def get_auth_url(self, msa: bool = False,
                     **additional_args) -> Tuple[str, str]: ...
    def set_token(self, response_url: str) -> None: ...