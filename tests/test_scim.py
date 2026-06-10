from __future__ import annotations

import httpx
from fastapi import FastAPI

from authub.scim import (
    ScimServer,
    StaticTokenAuthenticator,
)


def make_app() -> tuple[FastAPI, httpx.AsyncClient]:
    auth = StaticTokenAuthenticator({"tok-a": "tenant-a", "tok-b": "tenant-b"})
    server = ScimServer(authenticator=auth)
    app = FastAPI()
    server.attach(app)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    return app, client


HDR_A = {"Authorization": "Bearer tok-a"}
HDR_B = {"Authorization": "Bearer tok-b"}


async def test_post_user_creates_201() -> None:
    _, client = make_app()
    resp = await client.post(
        "/scim/v2/Users",
        json={"userName": "alice"},
        headers=HDR_A,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["userName"] == "alice"
    assert body["id"] is not None
    assert body["active"] is True
    assert "meta" in body
    assert body["meta"]["resourceType"] == "User"
    assert "Location" in resp.headers
    assert "/scim/v2/Users/" in resp.headers["Location"]


async def test_get_user_roundtrip() -> None:
    _, client = make_app()
    create = await client.post("/scim/v2/Users", json={"userName": "bob"}, headers=HDR_A)
    uid = create.json()["id"]

    get = await client.get(f"/scim/v2/Users/{uid}", headers=HDR_A)
    assert get.status_code == 200
    assert get.json()["userName"] == "bob"


async def test_get_user_not_found() -> None:
    _, client = make_app()
    resp = await client.get("/scim/v2/Users/no-such-id", headers=HDR_A)
    assert resp.status_code == 404
    body = resp.json()
    assert "urn:ietf:params:scim:api:messages:2.0:Error" in body["schemas"]
    assert body["status"] == "404"


async def test_list_users_filter_by_username() -> None:
    _, client = make_app()
    await client.post("/scim/v2/Users", json={"userName": "alice"}, headers=HDR_A)
    await client.post("/scim/v2/Users", json={"userName": "bob"}, headers=HDR_A)

    resp = await client.get(
        '/scim/v2/Users?filter=userName eq "alice"',
        headers=HDR_A,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["totalResults"] == 1
    assert body["Resources"][0]["userName"] == "alice"


async def test_list_users_invalid_filter() -> None:
    _, client = make_app()
    resp = await client.get('/scim/v2/Users?filter=userName co "a"', headers=HDR_A)
    assert resp.status_code == 400
    body = resp.json()
    assert body["scimType"] == "invalidFilter"


async def test_put_user_replaces() -> None:
    _, client = make_app()
    create = await client.post(
        "/scim/v2/Users",
        json={"userName": "alice", "displayName": "Alice"},
        headers=HDR_A,
    )
    uid = create.json()["id"]

    put = await client.put(
        f"/scim/v2/Users/{uid}",
        json={"userName": "alice", "displayName": "Alice Updated", "active": False},
        headers=HDR_A,
    )
    assert put.status_code == 200
    assert put.json()["displayName"] == "Alice Updated"
    assert put.json()["active"] is False


async def test_put_user_not_found() -> None:
    _, client = make_app()
    resp = await client.put(
        "/scim/v2/Users/no-such",
        json={"userName": "x"},
        headers=HDR_A,
    )
    assert resp.status_code == 404


async def test_patch_user_active_false() -> None:
    _, client = make_app()
    create = await client.post("/scim/v2/Users", json={"userName": "carol"}, headers=HDR_A)
    uid = create.json()["id"]

    patch = await client.patch(
        f"/scim/v2/Users/{uid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=HDR_A,
    )
    assert patch.status_code == 200
    assert patch.json()["active"] is False


async def test_patch_user_not_found() -> None:
    _, client = make_app()
    resp = await client.patch(
        "/scim/v2/Users/no-such",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=HDR_A,
    )
    assert resp.status_code == 404


async def test_delete_user_then_get_404() -> None:
    _, client = make_app()
    create = await client.post("/scim/v2/Users", json={"userName": "dave"}, headers=HDR_A)
    uid = create.json()["id"]

    delete = await client.delete(f"/scim/v2/Users/{uid}", headers=HDR_A)
    assert delete.status_code == 204

    get = await client.get(f"/scim/v2/Users/{uid}", headers=HDR_A)
    assert get.status_code == 404


async def test_duplicate_username_409() -> None:
    _, client = make_app()
    await client.post("/scim/v2/Users", json={"userName": "eve"}, headers=HDR_A)
    resp = await client.post("/scim/v2/Users", json={"userName": "eve"}, headers=HDR_A)
    assert resp.status_code == 409
    assert resp.json()["scimType"] == "uniqueness"


async def test_missing_bearer_401() -> None:
    _, client = make_app()
    resp = await client.get("/scim/v2/Users")
    assert resp.status_code == 401


async def test_wrong_bearer_401() -> None:
    _, client = make_app()
    resp = await client.get("/scim/v2/Users", headers={"Authorization": "Bearer bad-token"})
    assert resp.status_code == 401


async def test_tenant_isolation_get() -> None:
    _, client = make_app()
    create = await client.post("/scim/v2/Users", json={"userName": "frank"}, headers=HDR_A)
    uid = create.json()["id"]

    resp = await client.get(f"/scim/v2/Users/{uid}", headers=HDR_B)
    assert resp.status_code == 404


async def test_tenant_isolation_list() -> None:
    _, client = make_app()
    await client.post("/scim/v2/Users", json={"userName": "grace"}, headers=HDR_A)

    resp = await client.get("/scim/v2/Users", headers=HDR_B)
    assert resp.status_code == 200
    assert resp.json()["totalResults"] == 0


async def test_groups_crud() -> None:
    _, client = make_app()
    create = await client.post(
        "/scim/v2/Groups",
        json={"displayName": "admins"},
        headers=HDR_A,
    )
    assert create.status_code == 201
    gid = create.json()["id"]
    assert create.json()["displayName"] == "admins"

    get = await client.get(f"/scim/v2/Groups/{gid}", headers=HDR_A)
    assert get.status_code == 200
    assert get.json()["displayName"] == "admins"

    delete = await client.delete(f"/scim/v2/Groups/{gid}", headers=HDR_A)
    assert delete.status_code == 204

    gone = await client.get(f"/scim/v2/Groups/{gid}", headers=HDR_A)
    assert gone.status_code == 404


async def test_groups_patch_add_remove_member() -> None:
    _, client = make_app()

    user_resp = await client.post("/scim/v2/Users", json={"userName": "henry"}, headers=HDR_A)
    uid = user_resp.json()["id"]

    group_resp = await client.post("/scim/v2/Groups", json={"displayName": "eng"}, headers=HDR_A)
    gid = group_resp.json()["id"]

    patch_add = await client.patch(
        f"/scim/v2/Groups/{gid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": uid}]},
            ],
        },
        headers=HDR_A,
    )
    assert patch_add.status_code == 200
    assert any(m["value"] == uid for m in patch_add.json()["members"])

    patch_remove = await client.patch(
        f"/scim/v2/Groups/{gid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "remove", "path": "members", "value": [{"value": uid}]},
            ],
        },
        headers=HDR_A,
    )
    assert patch_remove.status_code == 200
    assert patch_remove.json()["members"] == []


async def test_service_provider_config() -> None:
    _, client = make_app()
    resp = await client.get("/scim/v2/ServiceProviderConfig", headers=HDR_A)
    assert resp.status_code == 200
    body = resp.json()
    assert body["patch"]["supported"] is True
    assert body["filter"]["supported"] is True


async def test_response_content_type_and_camel_case() -> None:
    _, client = make_app()
    resp = await client.post("/scim/v2/Users", json={"userName": "ivan"}, headers=HDR_A)
    assert "application/scim+json" in resp.headers["content-type"]
    body = resp.json()
    assert "userName" in body
    assert "totalResults" not in body


async def test_pagination() -> None:
    _, client = make_app()
    for i in range(5):
        await client.post("/scim/v2/Users", json={"userName": f"user{i}"}, headers=HDR_A)

    resp = await client.get("/scim/v2/Users?startIndex=1&count=2", headers=HDR_A)
    assert resp.status_code == 200
    body = resp.json()
    assert body["totalResults"] == 5
    assert body["itemsPerPage"] == 2
    assert len(body["Resources"]) == 2


async def test_list_response_schema() -> None:
    _, client = make_app()
    resp = await client.get("/scim/v2/Users", headers=HDR_A)
    assert resp.status_code == 200
    body = resp.json()
    assert "urn:ietf:params:scim:api:messages:2.0:ListResponse" in body["schemas"]
    assert "Resources" in body


async def test_resource_types_and_schemas() -> None:
    _, client = make_app()
    rt = await client.get("/scim/v2/ResourceTypes", headers=HDR_A)
    assert rt.status_code == 200

    sc = await client.get("/scim/v2/Schemas", headers=HDR_A)
    assert sc.status_code == 200


async def test_external_id_filter() -> None:
    _, client = make_app()
    await client.post(
        "/scim/v2/Users",
        json={"userName": "judy", "externalId": "ext-001"},
        headers=HDR_A,
    )
    resp = await client.get(
        '/scim/v2/Users?filter=externalId eq "ext-001"',
        headers=HDR_A,
    )
    assert resp.status_code == 200
    assert resp.json()["totalResults"] == 1
    assert resp.json()["Resources"][0]["userName"] == "judy"


async def test_patch_remove_required_field_returns_400_not_500() -> None:
    _, client = make_app()
    create = await client.post("/scim/v2/Users", json={"userName": "kent"}, headers=HDR_A)
    uid = create.json()["id"]

    resp = await client.patch(
        f"/scim/v2/Users/{uid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "remove", "path": "userName"}],
        },
        headers=HDR_A,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert "urn:ietf:params:scim:api:messages:2.0:Error" in body["schemas"]
    assert body["scimType"] == "invalidValue"


async def test_put_username_conflict_returns_409() -> None:
    _, client = make_app()
    await client.post("/scim/v2/Users", json={"userName": "alice"}, headers=HDR_A)
    bob = await client.post("/scim/v2/Users", json={"userName": "bob"}, headers=HDR_A)
    bob_id = bob.json()["id"]

    resp = await client.put(
        f"/scim/v2/Users/{bob_id}",
        json={"userName": "alice"},
        headers=HDR_A,
    )
    assert resp.status_code == 409
    assert resp.json()["scimType"] == "uniqueness"


async def test_group_create_duplicate_displayname_201_twice() -> None:
    _, client = make_app()
    r1 = await client.post("/scim/v2/Groups", json={"displayName": "engineers"}, headers=HDR_A)
    assert r1.status_code == 201
    r2 = await client.post("/scim/v2/Groups", json={"displayName": "engineers"}, headers=HDR_A)
    assert r2.status_code == 201
    assert r1.json()["id"] != r2.json()["id"]


async def test_group_patch_azure_member_remove() -> None:
    _, client = make_app()

    user1 = await client.post("/scim/v2/Users", json={"userName": "liam"}, headers=HDR_A)
    uid1 = user1.json()["id"]
    user2 = await client.post("/scim/v2/Users", json={"userName": "mia"}, headers=HDR_A)
    uid2 = user2.json()["id"]

    grp = await client.post("/scim/v2/Groups", json={"displayName": "ops"}, headers=HDR_A)
    gid = grp.json()["id"]

    await client.patch(
        f"/scim/v2/Groups/{gid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": uid1}, {"value": uid2}]},
            ],
        },
        headers=HDR_A,
    )

    resp = await client.patch(
        f"/scim/v2/Groups/{gid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "remove", "path": f'members[value eq "{uid1}"]'},
            ],
        },
        headers=HDR_A,
    )
    assert resp.status_code == 200
    remaining = [m["value"] for m in resp.json()["members"]]
    assert uid1 not in remaining
    assert uid2 in remaining


async def test_group_patch_azure_remove_unsupported_operator_400() -> None:
    _, client = make_app()
    grp = await client.post("/scim/v2/Groups", json={"displayName": "qa"}, headers=HDR_A)
    gid = grp.json()["id"]

    resp = await client.patch(
        f"/scim/v2/Groups/{gid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "remove", "path": 'members[value sw "usr_"]'},
            ],
        },
        headers=HDR_A,
    )
    assert resp.status_code == 400
    assert resp.json()["scimType"] == "invalidPath"


async def test_patch_remove_active_disables_user() -> None:
    _, client = make_app()
    create = await client.post("/scim/v2/Users", json={"userName": "noah"}, headers=HDR_A)
    uid = create.json()["id"]
    assert create.json()["active"] is True

    resp = await client.patch(
        f"/scim/v2/Users/{uid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "remove", "path": "active"}],
        },
        headers=HDR_A,
    )
    assert resp.status_code == 200
    assert resp.json()["active"] is False


async def test_pagination_negative_count_clamped() -> None:
    _, client = make_app()
    resp = await client.get("/scim/v2/Users?count=-1", headers=HDR_A)
    assert resp.status_code == 200
    body = resp.json()
    assert body["itemsPerPage"] >= 0
    assert body["startIndex"] >= 1


async def test_pagination_start_index_zero_clamped() -> None:
    _, client = make_app()
    for i in range(3):
        await client.post("/scim/v2/Users", json={"userName": f"page_user{i}"}, headers=HDR_A)

    resp = await client.get("/scim/v2/Users?startIndex=0&count=10", headers=HDR_A)
    assert resp.status_code == 200
    body = resp.json()
    assert body["startIndex"] == 1
    assert body["totalResults"] == 3


async def test_meta_location_uses_custom_prefix() -> None:
    from authub.scim import ScimServer, StaticTokenAuthenticator

    auth = StaticTokenAuthenticator({"tok": "t1"})
    server = ScimServer(authenticator=auth)
    app = FastAPI()
    server.attach(app, prefix="/api/scim/v2")
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    resp = await client.post(
        "/api/scim/v2/Users",
        json={"userName": "olivia"},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["meta"]["location"].startswith("/api/scim/v2/Users/")
    assert resp.headers["Location"].startswith("/api/scim/v2/Users/")

    user_id = body["id"]
    got = await client.get(
        f"/api/scim/v2/Users/{user_id}", headers={"Authorization": "Bearer tok"}
    )
    assert got.json()["meta"]["location"] == f"/api/scim/v2/Users/{user_id}"

    put = await client.put(
        f"/api/scim/v2/Users/{user_id}",
        json={"userName": "olivia"},
        headers={"Authorization": "Bearer tok"},
    )
    assert put.json()["meta"]["location"] == f"/api/scim/v2/Users/{user_id}"

    patched = await client.patch(
        f"/api/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers={"Authorization": "Bearer tok"},
    )
    assert patched.json()["meta"]["location"] == f"/api/scim/v2/Users/{user_id}"
