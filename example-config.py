mitreid_config = {
    "dbname": "example_db",
    "user": "example_user",
    "host": "example_address",
    "password": "secret"
}

keycloak_config = {    
    "auth_server": "https://example.org/auth",
    "realm": "myrealm",
    "client_id": "myClientId",
    "client_secret": "secret",
    "service_account": {
      "attribute_name": "voPersonID",
      "candidate": "id",
      "scope": "example.org"
    },
    "oidc_consent": False,
    "copy_dynamic_clients": False,
}