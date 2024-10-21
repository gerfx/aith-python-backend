import pytest
import base64
from starlette.testclient import TestClient

from lecture_4.demo_service.api.contracts import *
from lecture_4.demo_service.api.main import create_app
from lecture_4.demo_service.core.users import UserInfo, UserService, password_is_longer_than_8


demo_service = create_app()
client = TestClient(demo_service)

@pytest.fixture()
def register_user_request():
    return RegisterUserRequest(
        username="test_username",
        name="test_name",
        birthdate=datetime(2020, 1, 1),
        password=SecretStr("password9")
    )


@pytest.fixture()
def user_info():
    return UserInfo(
        username="test_username",
        name="test_name",
        birthdate=datetime(2020, 1, 1),
        role=UserRole.USER,
        password=SecretStr("password9")
    )


@pytest.fixture()
def user_entity(user_info):
    return UserEntity(
        uid=1,
        info=user_info
    )


@pytest.fixture()
def user_auth_request():
    return UserAuthRequest(
        username="test_username",
        password=SecretStr("password9")
    )


@pytest.fixture(scope="function")
def user_service():
    return UserService()


@pytest.fixture(scope="function")
def user_response():
    return UserResponse(
        uid=1,
        username="test_username",
        name="test_name",
        birthdate=datetime(2020, 1, 1),
        role=UserRole.USER
    )


def test_create_app():
    assert demo_service is not None


def test_password_no_longer_than_8():
    assert not password_is_longer_than_8("password")
    assert password_is_longer_than_8("password9")


def test_user_role():
    user_role = UserRole.USER
    assert user_role == UserRole.USER


def test_user_info(user_info):
    assert user_info.username == "test_username"
    assert user_info.name == "test_name"
    assert user_info.birthdate == datetime(2020, 1, 1)
    assert user_info.role == UserRole.USER
    assert user_info.password == SecretStr("password9")


def test_user_entity(user_entity):
    assert user_entity.uid == 1
    assert user_entity.info.username == "test_username"
    assert user_entity.info.name == "test_name"
    assert user_entity.info.birthdate == datetime(2020, 1, 1)
    assert user_entity.info.role == UserRole.USER
    assert user_entity.info.password == SecretStr("password9")


def test_register_user_request(register_user_request):
    assert register_user_request.username == "test_username"
    assert register_user_request.name == "test_name"
    assert register_user_request.birthdate == datetime(2020, 1, 1)
    assert register_user_request.password == SecretStr("password9")


def test_user_response(user_response, user_entity):
    assert user_response.uid == 1
    assert user_response.username == "test_username"
    assert user_response.name == "test_name"
    assert user_response.birthdate == datetime(2020, 1, 1)
    assert user_response.role == UserRole.USER

    user_response_from_entity = UserResponse.from_user_entity(user_entity)
    assert user_response.uid == 1
    assert user_response.username == "test_username"
    assert user_response.name == "test_name"
    assert user_response.birthdate == datetime(2020, 1, 1)
    assert user_response.role == UserRole.USER


def test_user_auth_request(user_auth_request):
    assert user_auth_request.username == "test_username"
    assert user_auth_request.password == SecretStr("password9")


def test_user_service(user_service, user_info):
    user_entity = user_service.register(user_info)
    assert user_entity.info.username == user_info.username
    assert user_entity.info.name == user_info.name
    assert user_entity.info.birthdate == user_info.birthdate
    assert user_entity.info.role == user_info.role
    assert user_entity.info.password == user_info.password

    assert user_service.get_by_username(user_info.username) == user_entity
    assert user_service.get_by_id(user_entity.uid) == user_entity

    user_service.grant_admin(user_entity.uid)
    assert user_entity.info.role == UserRole.ADMIN

    with pytest.raises(ValueError):
        user_service.grant_admin(2)


@pytest.fixture()
def demo_servicee():
    app = create_app()
    with TestClient(app) as client:
        yield client


def test_register_user(demo_servicee, user_service, register_user_request, user_response):
    request_data = register_user_request.model_dump()
    request_data['birthdate'] = request_data['birthdate'].isoformat()
    request_data['password'] = register_user_request.password.get_secret_value()

    response = demo_servicee.post("/user-register", json=request_data)
    assert response.status_code == 200
    assert response.json().get('name') == user_response.name
    assert response.json().get('username') == user_response.username
    assert response.json().get('role') == user_response.role
    assert datetime.fromisoformat(response.json().get('birthdate')) == user_response.birthdate


def test_get_user(demo_servicee, register_user_request, user_entity, user_response):
    request_data = register_user_request.model_dump()
    request_data['birthdate'] = request_data['birthdate'].isoformat()
    request_data['password'] = register_user_request.password.get_secret_value()

    admin_request_data = {
        "username": "admin",
        "name": "admin",
        "birthdate": datetime.fromtimestamp(0.0).isoformat(),
        "password": "superSecretAdminPassword123"
    }

    username = request_data["username"]
    password = request_data["password"]
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    user_auth_headers = {
    "Authorization": f"Basic {encoded_credentials}"
    }
    
    admin_username = admin_request_data["username"]
    admin_password = admin_request_data["password"]
    admin_credentials = f"{admin_username}:{admin_password}"
    admin_encoded_credentials = base64.b64encode(admin_credentials.encode()).decode()
    admin_auth_headers = {
    "Authorization": f"Basic {admin_encoded_credentials}"
    }
    first_post_resp = demo_servicee.post("/user-register", json=request_data)


    response = demo_servicee.post("/user-get", params={'id': first_post_resp.json().get("uid")}, headers=user_auth_headers)

    assert response.status_code == 200
    assert response.json().get('name') == user_response.name
    assert response.json().get('username') == user_response.username
    assert response.json().get('role') == user_response.role
    assert datetime.fromisoformat(response.json().get('birthdate')) == user_response.birthdate

    response = demo_servicee.post("/user-get", json={'id': user_entity.uid, 'username': user_entity.info.username})
    assert response.status_code == 401

    response = demo_servicee.post("/user-get", params={'id': user_entity.uid, 'username': user_entity.info.username},
                                  headers=user_auth_headers)

    assert response.status_code == 400

    response = demo_servicee.post("/user-get", params={}, headers=user_auth_headers)
    assert response.status_code == 400

    demo_servicee.post("/user-register", json=admin_request_data)
    response = demo_servicee.post("/user-get", params={"username": "admin"}, headers=admin_auth_headers)
    assert response.status_code == 200

    demo_servicee.post("/user-register", json=admin_request_data)
    response = demo_servicee.post("/user-get", params={"username": "invalid_username"}, headers=admin_auth_headers)
    assert response.status_code == 404

    auth_headers_bad = {
        "Authorization": "Basic YWRtaW46MTIz"
    }

    response = demo_servicee.post("/user-get", params={'id': first_post_resp.json().get("uid")},
                                  headers=auth_headers_bad)
    assert response.status_code == 401


def test_promote_user(demo_servicee, register_user_request, user_entity):
    admin_request_data = {
        "username": "admin",
        "name": "admin",
        "birthdate": datetime.fromtimestamp(0.0).isoformat(),
        "password": "superSecretAdminPassword123"
    }

    admin_username = admin_request_data["username"]
    admin_password = admin_request_data["password"]
    admin_credentials = f"{admin_username}:{admin_password}"
    admin_encoded_credentials = base64.b64encode(admin_credentials.encode()).decode()
    admin_auth_headers = {
    "Authorization": f"Basic {admin_encoded_credentials}"
    }

    demo_servicee.post("/user-register", json=admin_request_data)

    request_data = register_user_request.model_dump()
    request_data['birthdate'] = request_data['birthdate'].isoformat()
    request_data['password'] = register_user_request.password.get_secret_value()

    username = request_data["username"]
    password = request_data["password"]
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    user_auth_headers = {
    "Authorization": f"Basic {encoded_credentials}"
}

    first_post_resp = demo_servicee.post("/user-register", json=request_data)
    assert first_post_resp.status_code == 200

    resp = demo_servicee.post("/user-promote", params={'id': first_post_resp.json().get("uid")},
                              headers=user_auth_headers)
    assert resp.status_code == 403

    response = demo_servicee.post("/user-promote", params={'id': first_post_resp.json().get("uid")},
                                  headers=admin_auth_headers)
    assert response.status_code == 200

    invalid_admin_request_data = {
        "username": "invalid_admin",
        "name": "invalid_admin",
        "birthdate": datetime(2021, 1, 1).isoformat(),
        "password": "invalid"
    }

    response = demo_servicee.post("/user-register", json=invalid_admin_request_data)
    assert response.status_code == 400