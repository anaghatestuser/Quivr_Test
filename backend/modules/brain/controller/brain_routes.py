# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    hop_label = source_type + "->" + destination_type
    # A genuine policy block stops later checks in the same request context only
    # (a contextvar, not process-wide) so one blocked call never breaks the next request.
    _latch = getattr(gr_check, "_latch", None)
    if _latch is None:
        import contextvars as _cv
        _latch = gr_check._latch = _cv.ContextVar("lineaje_gr_blocked", default=None)
    _prior = _latch.get()
    if _prior:
        _log.warning("gr_client[%s]: skipping POST /enforce — request already blocked (%s)", hop_label, _prior[1])
        raise GRBlockedError(_prior[0], _prior[1])
    def _blk(o):
        if isinstance(o, dict):
            return any(_blk(o.get(k)) for k in ("skill_path", "skill_file", "path", "file_path", "data", "skill_manifest_path"))
        s = str(o or "")
        b = s.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if b.endswith(".md.blocked"): return True
        try:
            if b in ("skill.md", "skills.md") and _os.path.isfile(str(o) + ".blocked"): return True
        except Exception:
            pass
        return False
    if _blk(data) or _blk(context):
        _log.warning("gr_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called", hop_label)
        _latch.set(("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded"))
        raise GRBlockedError("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
    def _stub_client():
        # gr_stub_client.py (shipped next to instrumented files) loads .env, exchanges
        # the refresh token, and re-registers the site on unknown_site /
        # candidate_policies_mismatch — prefer it over the bare POST below.
        import sys as _s, importlib.util as _ilu
        from pathlib import Path as _P
        n = "_lineaje_gr_stub_client"
        if n in _s.modules: return _s.modules[n]
        if getattr(gr_check, "_no_stub_client", False): return None
        try:
            h = _P(__file__).resolve().parent
            c = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), None)
            if c is not None:
                spec = _ilu.spec_from_file_location(n, c)
                _s.modules[n] = m = _ilu.module_from_spec(spec)
                spec.loader.exec_module(m)
                if hasattr(m, "check") and hasattr(m, "SiteDescriptor"): return m
                _s.modules.pop(n, None)
        except Exception as exc:
            _s.modules.pop(n, None)
            _log.warning("gr_client[%s]: gr_stub_client.py not loadable (%s) — using inline client", hop_label, exc)
        gr_check._no_stub_client = True
        return None
    def _block(policy_id, reason):
        _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
        if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
            return data
        _latch.set((policy_id, reason))
        raise GRBlockedError(policy_id, reason)
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    _sc = _stub_client()
    if _sc is not None:
        try:
            _cp = [p if isinstance(p, dict) else {"policy_id": p} for p in (context.get("candidate_policies") or [])]
            _site = _sc.SiteDescriptor(site_id=context.get("site_id") or "", candidate_policies=_cp, fail_mode="BLOCK", source_type=source_type, destination_type=destination_type)
            _d = _sc.check(_site, data, tenant_id=tid, timeout=timeout)
        except Exception as exc:
            _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
            return data
        if _d.blocked and not getattr(_d, "infra_failure", False):
            _acts = _d.actions_applied or []
            _pid = (_acts[0].get("policy_id") if _acts and isinstance(_acts[0], dict) else "") or "unknown"
            return _block(_pid, _d.warning or "Request denied by policy enforcement.")
        if _d.blocked:
            _log.warning("gr_client[%s]: GR service unavailable (%s) — failing open", hop_label, _d.warning)
            return data
        return data if _d.payload is None else _d.payload
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    # Refresh token first: the GR service exchanges it for the access JWT it
    # calls the Data Service policy API with; a lineaje_pat_ PAT only
    # identifies the caller and cannot be exchanged.
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_REFRESH_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    params_key = "out_params" if destination_type == "agent" else "in_params"
    def _gr_js(o):
        # JSON form of non-JSON payloads (LangChain Document, pydantic models, ...).
        if hasattr(o, "page_content"):
            return {"page_content": o.page_content, "metadata": getattr(o, "metadata", None) or {}}
        for _m in ("model_dump", "dict", "to_dict"):
            _f = getattr(o, _m, None)
            if callable(_f):
                try:
                    return _f()
                except Exception:
                    pass
        if isinstance(o, (set, tuple)):
            return list(o)
        return str(o)
    def _gr_back(orig, new):
        # Map the (possibly masked) JSON back onto the caller's own objects.
        if new == _j.loads(_j.dumps(orig, default=_gr_js)):
            return orig
        if isinstance(orig, (list, tuple)) and isinstance(new, list) and len(orig) == len(new):
            _out = [_gr_back(a, b) for a, b in zip(orig, new)]
            return tuple(_out) if isinstance(orig, tuple) else _out
        if hasattr(orig, "page_content") and isinstance(new, dict) and "page_content" in new:
            import copy as _cp
            _c = _cp.copy(orig)
            _c.page_content = new["page_content"]
            if isinstance(new.get("metadata"), dict) and hasattr(_c, "metadata"):
                _c.metadata = new["metadata"]
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        return orig
    _base = url.rstrip("/")
    if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
    def _post(body):
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body, default=_gr_js).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            return _j.loads(resp.read())
    try:
        _sent = _j.loads(_j.dumps(data, default=_gr_js))
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": _sent}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
    except Exception as exc:
        _log.warning("gr_client[%s]: payload not serializable (%s) — failing open", hop_label, exc)
        return data
    result = None
    for _attempt in (0, 1):
        try:
            result = _post(body)
            break
        except Exception as exc:
            if isinstance(exc, _ue.HTTPError) and exc.code == 403:
                try: detail = _j.loads(exc.read()).get("detail", {})
                except Exception: detail = {}
                if not isinstance(detail, dict): detail = {"message": str(detail)}
                blocked_by = detail.get("blocked_by") or []
                if blocked_by or detail.get("error") == "request_blocked":
                    _pid = (blocked_by[0].get("policy_id") if isinstance(blocked_by[0], dict) else "") if blocked_by else ""
                    return _block(_pid or "unknown", detail.get("message", "Request denied by policy enforcement."))
                if _attempt == 0 and (body.get("site_id") or body.get("candidate_policies")):
                    # unknown_site / candidate_policies_mismatch: a site-manifest
                    # problem, not a policy verdict — re-evaluate without site scoping.
                    _log.warning("gr_client[%s]: %s — retrying without site_id", hop_label, detail.get("error") or detail.get("message") or "403")
                    body = {k: v for k, v in body.items() if k not in ("site_id", "candidate_policies")}
                    continue
            _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
            return data
    if not isinstance(result, dict):
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        return data
    return _gr_back(data, result["result"]["data"])
from typing import Dict
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from logger import get_logger
from middlewares.auth.auth_bearer import AuthBearer, get_current_user
from models import UserUsage
from modules.brain.dto.inputs import (
    BrainQuestionRequest,
    BrainUpdatableProperties,
    CreateBrainProperties,
)
from modules.brain.entity.brain_entity import PublicBrain, RoleEnum
from modules.brain.service.brain_authorization_service import has_brain_authorization
from modules.brain.service.brain_service import BrainService
from modules.brain.service.brain_user_service import BrainUserService
from modules.prompt.service.prompt_service import PromptService
from modules.user.entity.user_identity import UserIdentity
from repository.brain import get_question_context_from_brain

logger = get_logger(__name__)
brain_router = APIRouter()

prompt_service = PromptService()
brain_service = BrainService()
brain_user_service = BrainUserService()


@brain_router.get("/brains/", dependencies=[Depends(AuthBearer())], tags=["Brain"])
async def retrieve_all_brains_for_user(
    current_user: UserIdentity = Depends(get_current_user),
):
    """Retrieve all brains for the current user."""
    brains = brain_user_service.get_user_brains(current_user.id)
    return {"brains": brains}


@brain_router.get(
    "/brains/public", dependencies=[Depends(AuthBearer())], tags=["Brain"]
)
async def retrieve_public_brains() -> list[PublicBrain]:
    """Retrieve all Quivr public brains."""
    return brain_service.get_public_brains()


@brain_router.get(
    "/brains/default/", dependencies=[Depends(AuthBearer())], tags=["Brain"]
)
async def retrieve_default_brain(
    current_user: UserIdentity = Depends(get_current_user),
):
    """Retrieve or create the default brain for the current user."""
    brain = brain_user_service.get_default_user_brain_or_create_new(current_user)
    return {"id": brain.brain_id, "name": brain.name, "rights": "Owner"}


@brain_router.get(
    "/brains/{brain_id}/",
    dependencies=[
        Depends(AuthBearer()),
        Depends(
            has_brain_authorization(
                required_roles=[RoleEnum.Owner, RoleEnum.Editor, RoleEnum.Viewer]
            )
        ),
    ],
    tags=["Brain"],
)
async def retrieve_brain_by_id(brain_id: UUID):
    """Retrieve details of a specific brain by its ID."""
    brain_details = brain_service.get_brain_details(brain_id)
    if brain_details is None:
        raise HTTPException(status_code=404, detail="Brain details not found")
    try:
        import asyncio as _gr_asyncio
        brain_details = await _gr_asyncio.to_thread(gr_check, brain_details, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:b055de333d256b655f66214c1d61f5a1f7a552b68e6477cf5942afb56fa9ad34')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        brain_details = brain_details
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return brain_details


@brain_router.post("/brains/", dependencies=[Depends(AuthBearer())], tags=["Brain"])
async def create_new_brain(
    brain: CreateBrainProperties, current_user: UserIdentity = Depends(get_current_user)
):
    """Create a new brain for the user."""
    user_brains = brain_user_service.get_user_brains(current_user.id)
    user_usage = UserUsage(
        id=current_user.id,
        email=current_user.email,
    )
    user_settings = user_usage.get_user_settings()

    if len(user_brains) >= user_settings.get("max_brains", 5):
        raise HTTPException(
            status_code=429,
            detail=f"Maximum number of brains reached ({user_settings.get('max_brains', 5)}).",
        )

    new_brain = brain_service.create_brain(
        brain=brain,
        user_id=current_user.id,
    )
    if brain_user_service.get_user_default_brain(current_user.id):
        _lineaje_payload = f"Default brain already exists for user {current_user.id}"
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2783cc84ebc3342eac73dcd430cb8a3332ebe2db7331463cf33264026a3f14c4')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.info(f"Default brain already exists for user {current_user.id}")
        brain_user_service.create_brain_user(
            user_id=current_user.id,
            brain_id=new_brain.brain_id,
            rights=RoleEnum.Owner,
            is_default_brain=False,
        )
    else:
        _lineaje_payload = f"Creating default brain for user {current_user.id}."
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:2783cc84ebc3342eac73dcd430cb8a3332ebe2db7331463cf33264026a3f14c4')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.info(f"Creating default brain for user {current_user.id}.")
        brain_user_service.create_brain_user(
            user_id=current_user.id,
            brain_id=new_brain.brain_id,
            rights=RoleEnum.Owner,
            is_default_brain=True,
        )

    return {"id": new_brain.brain_id, "name": brain.name, "rights": "Owner"}


@brain_router.put(
    "/brains/{brain_id}/",
    dependencies=[
        Depends(AuthBearer()),
        Depends(has_brain_authorization([RoleEnum.Editor, RoleEnum.Owner])),
    ],
    tags=["Brain"],
)
async def update_existing_brain(
    brain_id: UUID, brain_update_data: BrainUpdatableProperties
):
    """Update an existing brain's configuration."""
    existing_brain = brain_service.get_brain_details(brain_id)
    if existing_brain is None:
        raise HTTPException(status_code=404, detail="Brain not found")

    brain_service.update_brain_by_id(brain_id, brain_update_data)

    if brain_update_data.prompt_id is None and existing_brain.prompt_id:
        prompt = prompt_service.get_prompt_by_id(existing_brain.prompt_id)
        if prompt and prompt.status == "private":
            prompt_service.delete_prompt_by_id(existing_brain.prompt_id)

    if brain_update_data.status == "private" and existing_brain.status == "public":
        brain_user_service.delete_brain_users(brain_id)

    return {"message": f"Brain {brain_id} has been updated."}


@brain_router.put(
    "/brains/{brain_id}/secrets-values",
    dependencies=[
        Depends(AuthBearer()),
    ],
    tags=["Brain"],
)
async def update_existing_brain_secrets(
    brain_id: UUID,
    secrets: Dict[str, str],
    current_user: UserIdentity = Depends(get_current_user),
):
    """Update an existing brain's secrets."""

    existing_brain = brain_service.get_brain_details(brain_id)

    if existing_brain is None:
        raise HTTPException(status_code=404, detail="Brain not found")

    if (
        existing_brain.brain_definition is None
        or existing_brain.brain_definition.secrets is None
    ):
        raise HTTPException(
            status_code=400,
            detail="This brain does not support secrets.",
        )

    is_brain_user = (
        brain_user_service.get_brain_for_user(
            user_id=current_user.id,
            brain_id=brain_id,
        )
        is not None
    )

    if not is_brain_user:
        raise HTTPException(
            status_code=403,
            detail="You are not authorized to update this brain.",
        )

    secrets_names = [secret.name for secret in existing_brain.brain_definition.secrets]

    for key, value in secrets.items():
        if key not in secrets_names:
            raise HTTPException(
                status_code=400,
                detail=f"Secret {key} is not a valid secret.",
            )
        if value:
            brain_service.update_secret_value(
                user_id=current_user.id,
                brain_id=brain_id,
                secret_name=key,
                secret_value=value,
            )

    return {"message": f"Brain {brain_id} has been updated."}


@brain_router.post(
    "/brains/{brain_id}/default",
    dependencies=[Depends(AuthBearer()), Depends(has_brain_authorization())],
    tags=["Brain"],
)
async def set_brain_as_default(
    brain_id: UUID, user: UserIdentity = Depends(get_current_user)
):
    """Set a brain as the default for the current user."""
    brain_user_service.set_as_default_brain_for_user(user.id, brain_id)
    return {"message": f"Brain {brain_id} has been set as default brain."}


@brain_router.post(
    "/brains/{brain_id}/documents",
    dependencies=[Depends(AuthBearer()), Depends(has_brain_authorization())],
    tags=["Brain"],
)
async def get_question_context_for_brain(
    brain_id: UUID, question: BrainQuestionRequest
):
    # TODO: Move this endpoint to AnswerGenerator service
    """Retrieve the question context from a specific brain."""
    try:
        import asyncio as _gr_asyncio
        brain_id = await _gr_asyncio.to_thread(gr_check, brain_id, "agent", "llm", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:edb91d16984f1a1eb678dd5e60bc39403df873da12400e88d5e8be07f9114dd1')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        brain_id = brain_id
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->llm' — passing data through unchecked")
    context = get_question_context_from_brain(brain_id, question.question)
    return {"docs": context}
