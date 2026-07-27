"""Firebase RTDB + Supabase RLS-off exposure — pure parsers + end-to-end reads."""

import base64
import json

import pytest

from moonmcp import server as srv
from moonmcp.recon import firebase as fb
from moonmcp.recon import supabase as sb


# -- Firebase pure -----------------------------------------------------------
def test_parse_firebase_config():
    js = "var firebaseConfig={apiKey:'AIzaX',projectId:'my-proj',databaseURL:'https://my-proj.firebaseio.com'};"
    cfg = fb.parse_firebase_config(js)
    assert cfg["databaseURL"] == "https://my-proj.firebaseio.com" and cfg["projectId"] == "my-proj"
    # newer regional RTDB host, no explicit config object
    bare = "fetch('https://app-default-rtdb.europe-west1.firebasedatabase.app/x.json')"
    assert fb.parse_firebase_config(bare)["databaseURL"].endswith(".firebasedatabase.app")


def test_rtdb_probe_url_strips_path():
    assert fb.rtdb_probe_url("https://x.firebaseio.com/ignored") == "https://x.firebaseio.com/.json?shallow=true"


def test_assess_rtdb():
    assert fb.assess_rtdb(200, '{"a":true}')["verdict"] == "confirmed"
    assert fb.assess_rtdb(200, "null")["verdict"] == "confirmed"
    assert fb.assess_rtdb(401, '{"error":"Permission denied"}')["verdict"] == "protected"
    assert fb.assess_rtdb(200, '{"error":"Permission denied"}')["verdict"] == "protected"
    assert fb.assess_rtdb(200, "<html>not json</html>") is None


# -- Supabase pure -----------------------------------------------------------
def _anon_jwt(role="anon"):
    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256'})}.{seg({'role': role, 'iss': 'supabase'})}.aFakeSignature1234567"


def test_parse_supabase_config():
    key = _anon_jwt("anon")
    js = f"const c=createClient('https://abcdefghijklmnop.supabase.co','{key}')"
    cfg = sb.parse_supabase_config(js)
    assert cfg["url"] == "https://abcdefghijklmnop.supabase.co"
    assert cfg["anon_key"] == key and cfg["key_type"] == "anon-jwt"
    # a service-role JWT is not picked as the anon key
    assert "anon_key" not in sb.parse_supabase_config(f"k='{_anon_jwt('service_role')}'")


def test_parse_tables_and_assess():
    assert sb.parse_tables('{"definitions":{"users":{},"rpc_x":{}},"paths":{}}') == ["users"]
    assert sb.assess_table(200, '[{"id":1}]') is True
    assert sb.assess_table(200, "[]") is False
    assert sb.assess_table(401, '{"message":"permission denied"}') is False


# -- end-to-end --------------------------------------------------------------
@pytest.mark.asyncio
async def test_firebase_exposure_detects_open_rtdb(local_server, fresh_context):
    base, _ = local_server
    res = await srv.firebase_exposure(target=f"{base}/fbapp")
    assert res["verdict"] == "confirmed" and res["severity"] == "high", res
    assert res["config"]["projectId"] == "demo-proj"
    assert "firestore_lead" in res


@pytest.mark.asyncio
async def test_firebase_exposure_no_config(local_server, fresh_context):
    base, _ = local_server
    res = await srv.firebase_exposure(target=f"{base}/fbapp-noconfig")
    assert res["verdict"] == "no_firebase_config"


@pytest.mark.asyncio
async def test_supabase_exposure_detects_rls_off(local_server, fresh_context):
    base, _ = local_server
    res = await srv.supabase_exposure(target=f"{base}/", project_url=base, anon_key=_anon_jwt("anon"))
    assert res["verdict"] == "confirmed", res
    assert res["rls_off_tables"] == ["users"] and res["tables_discovered"] == 2


@pytest.mark.asyncio
async def test_cloud_db_tools_registered():
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert {"firebase_exposure", "supabase_exposure"} <= tools
