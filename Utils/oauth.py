from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient

"""Creating a Access Token using the Client Credentials flow
:param issuer: The token endpoint, must be HTTPS.
:param client_id: Client id obtained during registration
:param client_secret: Client secret obtained during registration
:return: An access token
"""


def client_credentials_grant(issuer, clientId, clientSecret):
    tokenUrl = issuer + "/protocol/openid-connect/token"

    try:
        print("[client_credentials_grant] Get access token from " + issuer)
        client = BackendApplicationClient(client_id=clientId)
        oauth = OAuth2Session(client=client)
        response = oauth.fetch_token(token_url=tokenUrl, client_id=clientId, client_secret=clientSecret)
        print("[client_credentials_grant] Access Token: " + response["access_token"])
    except Exception as e:
        print("[client_credentials_grant] Failed to get access token")
        print(e)
        raise SystemExit(1)
    return response["access_token"]
