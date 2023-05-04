import config
import json
import logging
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from Keycloak.KeycloakOidcClientApi import KeycloakOidcClientApi
from Utils.common import get_keycloak_issuer
from Utils.oauth import client_credentials_grant
import sys


def map_token_endpoint_value(key):
    if key == "SECRET_POST":
        return "client-secret"
    elif key == "SECRET_BASIC":
        return "client-secret"
    elif key == "SECRET_JWT":
        return "client-secret-jwt"
    elif key == "PRIVATE_KEY":
        return "client-jwt"
    elif key == "NONE":
        return "client-secret"

def sync(dry_run):
    pathname = str(os.path.dirname(os.path.realpath(__file__)))
    logging.basicConfig(
        filename=pathname + "/log/main.log",
        level=logging.DEBUG,
        filemode="a",
        format="%(asctime)s - %(message)s",
    )

    connect_oidc_str = (
        "dbname='" + config.mitreid_config['dbname']
        + "' user='" + config.mitreid_config['user']
        + "' host='" + config.mitreid_config['host']
        + "' password='" + config.mitreid_config['password'] + "'"
    )

    try:
        conn_oidc = psycopg2.connect(connect_oidc_str)
    except Exception as e:
        logging.error("Could not connect to MITREid Connect DB")
        logging.error(e)
        raise SystemExit("Could not connect to MITREid Connect DB")

    # Create psycopg2 cursor that can execute queries
    cursor_oidc = conn_oidc.cursor(cursor_factory=RealDictCursor)
    
    dynamic_registrations = ""
    if not config.keycloak_config["copy_dynamic_clients"]:
        dynamic_registrations = """WHERE
        NOT det.dynamically_registered"""

    # Initialise connection to MITREid Connect DB
    oidc_query = """SELECT
        det.client_name,
        det.client_id,
        det.client_description,
        det.logo_uri,
        det.tos_uri,
        det.policy_uri,
        det.client_uri,
        det.token_endpoint_auth_method,
        det.client_secret,
        det.token_endpoint_auth_signing_alg,
        det.jwks,
        det.jwks_uri,
        det.access_token_validity_seconds,
        det.id_token_validity_seconds,
        det.reuse_refresh_tokens,
        det.refresh_token_validity_seconds,
        det.device_code_validity_seconds,
        det.dynamically_registered,
        det.code_challenge_method,
        string_agg(DISTINCT red.redirect_uri, ',') AS redirect_uri_list,
        string_agg(DISTINCT cont.contact, ',') AS contact_list,
        string_agg(DISTINCT scope.scope, ',') AS scope_list,
        string_agg(DISTINCT grantt.grant_type, ',') AS grant_type_list
    FROM
        client_details as det
    LEFT JOIN
        client_redirect_uri AS red
        ON det.id=red.owner_id
    LEFT JOIN
        client_contact AS cont
        ON det.id=cont.owner_id
    LEFT JOIN
        client_scope AS scope
        ON det.id=scope.owner_id
    LEFT JOIN
        client_grant_type AS grantt
        ON det.id=grantt.owner_id
    %s
    GROUP BY
        det.client_name,
        det.client_id,
        det.client_description,
        det.logo_uri,
        det.tos_uri,
        det.policy_uri,
        det.client_uri,
        det.token_endpoint_auth_method,
        det.client_secret,
        det.token_endpoint_auth_signing_alg,
        det.jwks,
        det.jwks_uri,
        det.access_token_validity_seconds,
        det.id_token_validity_seconds,
        det.reuse_refresh_tokens,
        det.refresh_token_validity_seconds,
        det.device_code_validity_seconds,
        det.dynamically_registered,
        det.code_challenge_method;""" % (dynamic_registrations)

    # Select MITREid Connect clients
    logging.debug("Retrieving client details from MITREid Connect DB")
    try:
        cursor_oidc.execute(oidc_query)
    except Exception as e:
        logging.error("Could not retrieve client details from MITREid Connect DB")
        logging.error(e)
        raise SystemExit("Could not retrieve client details from MITREid Connect DB")

    client_details = cursor_oidc.fetchall()
    client_details = [dict(row) for row in client_details]

    cursor_oidc.close()
    conn_oidc.close()

    access_token = client_credentials_grant(
        get_keycloak_issuer(config.keycloak_config),
        config.keycloak_config["client_id"],
        config.keycloak_config["client_secret"],
    )

    # Map Query result to Keycloak ClientRepresentation object (JSON)
    keycloak_client_list = []

    keycloak_agent = KeycloakOidcClientApi(config.keycloak_config['auth_server'], config.keycloak_config['realm'], access_token)
    realm_default_client_scopes = keycloak_agent.get_realm_default_client_scopes()
    default_client_scopes = []
    for scope in realm_default_client_scopes["response"]:
        default_client_scopes.append(scope["name"])

    logging.debug("scopes: " + str(json.dumps(default_client_scopes)))

    # keycloak_client_list = json.dumps(keycloak_client_list)
    logging.debug("clients: " + str(json.dumps(keycloak_client_list)))

    if not dry_run:
        for client in client_details:
            request_data = format_keycloak_client_object(client, default_client_scopes, config.keycloak_config)
            logging.debug("create client: " + str(request_data))
            response = keycloak_agent.create_client((request_data))
            if response["status"] == 201:
                client_id = response["response"]["clientId"]
                if "id" in response["response"]:
                    external_id = response["response"]["id"]
                else:
                    response_external_id = keycloak_agent.get_client_by_id(client_id)
                    external_id = response_external_id["response"]["id"]
                if client["dynamically_registered"]:
                    logging.info("Registration Access Token for client `" + str(client_id) + "`: " + str(response["response"]["registrationAccessToken"]))
                else:
                    create_client_scopes(keycloak_agent, external_id, request_data)
                if request_data["attributes"]["oauth2.token.exchange.grant.enabled"] == True:
                    keycloak_agent.update_client_authz_permissions(external_id, "enable")
                if response["response"]["serviceAccountsEnabled"]:
                    update_service_account(
                        keycloak_agent, external_id, response["response"], config.keycloak_config["service_account"]
                    )


def format_keycloak_client_object(msg, realm_default_client_scopes, keycloak_config):
    json_template = '{"attributes":{"client_credentials.use_refresh_token":"false","oauth2.device.authorization.grant.enabled":"false","oauth2.token.exchange.grant.enabled":false,"oidc.ciba.grant.enabled":"false","refresh.token.max.reuse":"0","revoke.refresh.token":"false","use.jwks.string":"false","use.jwks.url":"false","use.refresh.tokens":"false"},"directAccessGrantsEnabled":false,"implicitFlowEnabled":false,"publicClient":false,"serviceAccountsEnabled":false,"standardFlowEnabled":false,"webOrigins":["+"]}'
    new_msg = json.loads(json_template)
    new_msg["defaultClientScopes"] = realm_default_client_scopes
    if "oidc_consent" in keycloak_config:
        new_msg["consentRequired"] = keycloak_config["oidc_consent"]
    else:
        new_msg["consentRequired"] = False
    if "client_name" in msg and msg["client_name"]:
        new_msg["name"] = msg.pop("client_name")
    if "client_id" in msg and msg["client_id"]:
        new_msg["clientId"] = msg.pop("client_id")
    if "client_description" in msg and msg["client_description"]:
        new_msg["description"] = msg.pop("client_description")
    if "client_uri" in msg and msg["client_uri"]:
        new_msg["baseUrl"] = msg.pop("client_uri")
    if "logo_uri" in msg and msg["logo_uri"]:
        new_msg["attributes"]["logoUri"] = msg.pop("logo_uri")
    if "policy_uri" in msg and msg["policy_uri"]:
        new_msg["attributes"]["policyUri"] = msg.pop("policy_uri")
    if "tos_uri" in msg and msg["tos_uri"]:
        new_msg["attributes"]["tosUri"] = msg.pop("tos_uri")
    if "contact_list" in msg and msg["contact_list"]:
        new_msg["attributes"]["contacts"] = msg.pop("contact_list")
    if "redirect_uri_list" in msg and msg["redirect_uri_list"]:
        new_msg["redirectUris"] = msg.pop("redirect_uri_list").split(",")
    if "scope_list" in msg and msg["scope_list"]:
        new_msg["optionalClientScopes"] = msg.pop("scope_list").split(",")
        if "openid" in new_msg["optionalClientScopes"]:
            new_msg["optionalClientScopes"].remove("openid")
    if "grant_type_list" in msg and msg["grant_type_list"]:
        grant_type_list = msg.pop("grant_type_list").split(",")
        for grant_type in grant_type_list:
            if grant_type == "authorization_code":
                new_msg["standardFlowEnabled"] = True
            if grant_type == "client_credentials":
                new_msg["serviceAccountsEnabled"] = True
            if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
                new_msg["attributes"]["oauth2.token.exchange.grant.enabled"] = True
            if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
                new_msg["attributes"]["oauth2.device.authorization.grant.enabled"] = True
            if grant_type == "implicit":
                new_msg["implicitFlowEnabled"] = True
    if "token_endpoint_auth_method" in msg and msg["token_endpoint_auth_method"]:
        if msg["token_endpoint_auth_method"] == "NONE":
            new_msg["publicClient"] = True
        new_msg["clientAuthenticatorType"] = map_token_endpoint_value(msg.pop("token_endpoint_auth_method"))
    if "client_secret" in msg and msg["client_secret"]:
        new_msg["secret"] = msg.pop("client_secret")
    if "token_endpoint_auth_signing_alg" in msg and msg["token_endpoint_auth_signing_alg"]:
        new_msg["attributes"]["token.endpoint.auth.signing.alg"] = msg.pop("token_endpoint_auth_signing_alg")
    if "jwks" in msg and msg["jwks"]:
        new_msg["attributes"]["use.jwks.string"] = "true"
        jwks_string = msg.pop("jwks")
        new_msg["attributes"]["jwks.string"] = jwks_string.replace('"','\"')
    if "jwks_uri" in msg and msg["jwks_uri"]:
        new_msg["attributes"]["use.jwks.url"] = True
        new_msg["attributes"]["jwks.url"] = msg.pop("jwks_uri")
    if "code_challenge_method" in msg and msg["code_challenge_method"]:
        new_msg["attributes"]["pkce.code.challenge.method"] = msg.pop("code_challenge_method")
    if "refresh_token_validity_seconds" in msg and msg["refresh_token_validity_seconds"]:
        new_msg["attributes"]["client.offline.session.idle.timeout"] = str(msg.pop("refresh_token_validity_seconds"))
        if "reuse_refresh_token" in msg and msg["reuse_refresh_token"]:
            rotate_refresh_token = str(not msg.pop("reuse_refresh_token"))
            new_msg["attributes"]["revoke.refresh.token"] = rotate_refresh_token.lower()
    if "access_token_validity_seconds" in msg and msg["access_token_validity_seconds"]:
        if msg["access_token_validity_seconds"] < 60:
            new_msg["attributes"]["access.token.lifespan"] = "60"
        else:
            new_msg["attributes"]["access.token.lifespan"] = str(msg.pop("access_token_validity_seconds"))
    if "device_code_validity_seconds" in msg and msg["device_code_validity_seconds"]:
        new_msg["attributes"]["oauth2.device.code.lifespan"] = str(msg.pop("device_code_validity_seconds"))
    if "id_token_timeout_seconds" in msg and msg["id_token_timeout_seconds"]:
        new_msg["attributes"]["id.token.lifespan"] = str(msg.pop("id_token_timeout_seconds"))
    if new_msg["standardFlowEnabled"] == True or new_msg["attributes"]["oauth2.device.authorization.grant.enabled"] == True:
        new_msg["consentRequired"] = True
    return new_msg


# Update the optional client scopes of the client
def create_client_scopes(agent, client_uuid, client_config):
    realm_client_scopes = agent.sync_realm_client_scopes()
    new_optional_client_scopes = client_config["optionalClientScopes"]

    # Custom scopes that are not created in Keycloak
    create_client_scopes = list(set(new_optional_client_scopes) - set(realm_client_scopes.keys()))
    for scope in create_client_scopes:
        # Create custom scope
        agent.create_realm_client_scopes(scope)
    
    # Get updated client scopes
    realm_client_scopes = agent.sync_realm_client_scopes()

    for add_scope in create_client_scopes:
        agent.add_client_scope_by_id(client_uuid, realm_client_scopes[add_scope])

# Update the optional client scopes of the client
def update_service_account(agent, client_uuid, current_client_config, keycloak_config):
    service_account_profile = agent.get_service_account_user(client_uuid)
    agent.update_user(service_account_profile["response"], current_client_config, keycloak_config)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "-n":
        dry_run_flag = True
    else:
        dry_run_flag = False
    sync(dry_run_flag)
